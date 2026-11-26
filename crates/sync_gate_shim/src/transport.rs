//! Owned, cancellable I/O workers. No worker owns a process handle.
use crate::{BUF, Reader, Writer};
use interprocess::local_socket::Stream;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(crate) const TICK: Duration = Duration::from_millis(5);

/// One trim per successful hub session, after the relay workers have been created.
pub(crate) fn trim_working_set() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::{
            Memory::SetProcessWorkingSetSizeEx, Threading::GetCurrentProcess,
        };
        // SAFETY: the pseudo handle is our process; SIZE_T(-1), SIZE_T(-1) requests a trim.
        SetProcessWorkingSetSizeEx(GetCurrentProcess(), usize::MAX, usize::MAX, 0);
    }
}

pub(crate) struct Worker {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl Worker {
    pub(crate) fn budgeted(
        budget: &mut Option<usize>,
        f: impl FnOnce(Arc<AtomicBool>) + Send + 'static,
    ) -> io::Result<Self> {
        if let Some(left) = budget {
            if *left == 0 {
                return Err(io::Error::other("injected thread creation failure"));
            }
            *left -= 1;
        }
        Self::start(f)
    }
    pub(crate) fn start(f: impl FnOnce(Arc<AtomicBool>) + Send + 'static) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || f(flag))?;
        Ok(Self { stop, thread })
    }

    pub(crate) fn cancel(&self) {
        self.stop.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            // SAFETY: the join handle owns this thread handle until the worker is dropped.
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(self.thread.as_raw_handle());
            }
        }
    }

    pub(crate) fn finish(self, until: Instant) {
        while !self.thread.is_finished() && Instant::now() < until {
            self.cancel();
            std::thread::sleep(TICK);
        }
        if self.thread.is_finished() {
            let _ = self.thread.join();
        }
    }
}

/// The session retains this owner until both hub workers have stopped.
pub(crate) struct Connection {
    stream: Arc<Stream>,
    closed: Arc<AtomicBool>,
}

impl Connection {
    pub(crate) fn new(stream: Stream) -> Self {
        Self {
            stream: Arc::new(stream),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn halves(&self) -> (Reader, Writer) {
        let shared = || Shared {
            stream: self.stream.clone(),
            closed: self.closed.clone(),
        };
        (
            Box::new(BufReader::with_capacity(BUF, shared())),
            Box::new(shared()),
        )
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        #[cfg(unix)]
        {
            let Stream::UdSocket(s) = &*self.stream;
            let _ = s.inner().shutdown(std::net::Shutdown::Both);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsHandle, AsRawHandle};
            let Stream::NamedPipe(s) = &*self.stream;
            // SAFETY: the connection retains the pipe while cancelling its outstanding I/O.
            unsafe {
                windows_sys::Win32::System::IO::CancelIoEx(
                    s.inner().as_handle().as_raw_handle(),
                    std::ptr::null(),
                );
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}

struct Shared {
    stream: Arc<Stream>,
    closed: Arc<AtomicBool>,
}
impl Read for Shared {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(0);
        }
        (&*self.stream).read(b)
    }
}
impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        (&*self.stream).write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Shared {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.closed.load(Ordering::SeqCst) {
            let Stream::NamedPipe(s) = &*self.stream;
            // Discard pending bytes on a cancelled connection instead of entering flush limbo.
            s.inner().assume_flushed();
        }
    }
}
