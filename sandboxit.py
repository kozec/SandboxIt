#!/usr/bin/env python2
from subprocess import Popen
from threading import Lock
from errno import EACCES, EPERM, ENOENT
import os, sys, time, cPickle, hashlib, argparse
HAVE_FUSE = False
verbose = False

try:
	from fuse import FUSE, FuseOSError, Operations
	HAVE_FUSE = True
except ImportError: pass


class Sandbox(object):
	"""
	Sandbox with ID and bunch of settings.
	
	Default sandbox has:
	 - X11 access, inlcuding nvidia device nodes
	 - network access
	 - pulseaudio access
	 - read-only access to /usr, /lib, /lib64, /bin, /sbin, /etc and /opt
	 - _no_ access to home folder
	 - read-write access _redirected_ home folder
	 - its own, private, /tmp, /proc and /dev
	 - read-write access to /dev/input
	"""
	
	def __init__(self, id):
		self.id = id
		self.path = os.path.expanduser("~/.local/share/sandboxit/%s" % (id,))
		self.home = os.path.join(self.path, "home")
		self.overlays = os.path.join("/tmp", "sandboxit", id)
		self.tmp = os.path.join("/tmp", "sandboxit", id, "tmp")
		self.net, self.pulse, self.x11 = True, True, True
		self.ipc = False
		self._overlay_fses = []
		self.binds = [
			Bind("/proc", type=Bind.PROCFS),
			Bind("/dev", type=Bind.DEVTMPFS),
			Bind("/dev/input", "/dev/input"),
			Bind("/tmp", self.tmp, read_write=True),
			# Home folder 'redirection'
			Bind(os.environ["HOME"], self.home, read_write=True),
			# All what follows is mounted read-only
			Bind("/opt/"),
			Bind("/etc/"),
			Bind("/usr/"),
			Bind("/bin/"),
			Bind("/sbin/"),
		] + [
			# /lib, /lib32 and /lib64 binds, for whatever exists
			Bind(x) for x in ("/lib/", "/lib32/", "/lib64/")
			if os.path.exists(x)
		]
	
	
	@staticmethod
	def for_binary(binary_path):
		"""
		Creates sandbox for binary. Such sandbox has id derived from binary
		as xyz-reallylongsha256ofentirebinarypath where xyz is binary name
		_without_ path.
		"""
		id = "%s-%s" % (os.path.split(binary_path)[-1], hashlib.sha256(binary_path).hexdigest())
		sandbox = Sandbox(id)
		sandbox.check()
		cfb = os.path.join(sandbox.path, "created-for-binary")
		if not os.path.exists(cfb):
			file(cfb, "w").write(binary_path)
		
		return sandbox
	
	
	def check(self):
		"""
		Creates required directories, config file etc...
		Throws exception if anything fails.
		Returns self.
		"""
		for path in (self.path, self.home, self.tmp, self.overlays):
			if not os.path.exists(path):
				os.makedirs(path)
				if verbose:
					print >>sys.stderr, "Created:", path
		return self
	
	
	def accessible(self, filename):
		"""
		Returns True if specified file should be accessible from whitin sandbox
		"""
		filename = os.path.abspath(filename)
		for bind in self.binds:
			if bind.src is not None:
				if filename.startswith(bind.src):
					return True
			elif filename.startswith(bind.dest):
				if bind.type in (Bind.DEVTMPFS, Bind.PROCFS, Bind.TMPFS):
					# TODO: This probably breaks more than it fixes :(
					return True
		if filename.startswith("/tmp"):
			# TODO: this as well :(
			return True
		return False
	
	
	def create_overlay(self, real_path):
		if not HAVE_FUSE:
			print >>sys.stderr, "Sandbox needs overlay, but fuse python module is not available"
			print >>sys.stderr, "Install python-fusepy to fix this problem."
			sys.exit(1)
		rw_path = os.path.join(self.path, "rw-" + real_path.replace("/", ""))
		tmp_path = os.path.join(self.overlays, "overlay-%s-%s" % (
				os.getpid(), real_path.replace("/", "")))
		for path in (rw_path, tmp_path):
			if not os.path.exists(path):
				os.makedirs(path)
		overlayfs = FuseProcess(sandboxit_overlay(real_path, rw_path), tmp_path)
		overlayfs.start()
		self._overlay_fses.append(overlayfs)
		return Bind(real_path, type=Bind.OVERLAY, overlay=tmp_path)
	
	
	def execute(self, binary, arguments=[]):
		"""
		Executes binary in this sandbox
		"""
		# Initialize
		home = os.path.abspath(os.path.expanduser("~"))
		bwargs = [ find_binary("bwrap"), "--die-with-parent", "--unshare-pid",
			"--unshare-user-try", "--unshare-uts", "--unshare-cgroup-try" ]
		
		# Share net, ipc, X11... if needed
		if not self.net: bwargs += [ "--unshare-net" ]
		if not self.ipc: bwargs += [ "--unshare-ipc" ]
		if self.x11:     bwargs += self._enable_x11()
		if self.pulse:   bwargs += self._enable_pulseaudio()
		
		# Special case, check if current directory is accessible from whitin sandbox
		cwd = os.path.abspath(os.getcwd())
		if HAVE_FUSE and not self.accessible(cwd):
			# ... and read-only Bind if needed
			if cwd == home:
				print >>sys.stderr, "Warning: I'd mount", cwd, "as overlay, but I don't as it is your home directory"
			else:
				if verbose:
					print >>sys.stderr, "Mounting", cwd + ", current directory, with overlay in sandbox"
				self.binds.append(self.create_overlay(cwd))
		
		# Another special case, check if binary is accessible from whitin sandbox
		if HAVE_FUSE and not self.accessible(binary):
			# ... and read-only Bind if needed
			path = os.path.split(binary)[0]
			if path == home:
				print >>sys.stderr, "Warning: I'd mount", path, "as overlay, but I don't as it isyour home directory"
			else:
				if verbose:
					print >>sys.stderr, "Mounting", path, "with overlay in sandbox"
				self.binds.append(self.create_overlay(path))
		
		# Add binds
		ljoin = lambda j , k: j + k
		bwargs += reduce(ljoin, [ x.to_args() for x in self.binds ], [])
		
		# Add binary & args
		bwargs += [ binary ] + arguments
		
		# Execute
		if verbose:
			print >>sys.stderr, "Executing:", " ".join(bwargs)
		Popen(bwargs).communicate()
		
		for o in self._overlay_fses:
			o.umount()
	
	
	def _enable_x11(self):
		""" Returns argument list to add """
		args = [ "--bind", "/tmp/.X11-unix", "/tmp/.X11-unix",
				 "--setenv", "DISPLAY", os.environ.get("DISPLAY") ]
		if "XAUTHORITY" in os.environ:
			if verbose:
				print >>sys.stderr, "Copying over", "XAUTHORITY file"
			(open(os.path.join(self.tmp, "XAUTHORITY"), "wb")
					.write(open(os.environ["XAUTHORITY"], "rb").read()))
			args += [ "--setenv", "XAUTHORITY", "/tmp/XAUTHORITY" ]
		# Needed for GLX
		if os.path.lexists("/dev/nvidia0"):
			for name in os.listdir("/dev/"):
				if "nvidia" in name:
					devpath = os.path.join("/dev", name)
					args += [ "--dev-bind", devpath, devpath ]
		return args
	
	
	def _enable_pulseaudio(self):
		""" Returns argument list to add """
		# Find socket
		socket = None
		pulsepaths = [ os.path.expanduser(x) for x in ("~/.pulse", "~/.config/pulse")  ]
		for path in pulsepaths:
			if os.path.exists(path):
				runtime_dir = [ x for x in os.listdir(path) if "runtime" in x ][0]
				runtime_dir = os.readlink(os.path.join(path, runtime_dir))
				socket_path = os.path.join(runtime_dir, "native")
				if os.path.exists(socket_path):
					socket = socket_path
					break
		if socket is None:
			socket_path = os.path.join("/run", "user", str(os.getuid()), "pulse", "native")
			if os.path.exists(socket_path):
				socket = socket_path
		if socket is None:
			print >>sys.stderr, "Warning: Failed to determine pulseaudio socket"
			return []
		# Find cookie
		cookie = None
		for path in ("~/.pulse/cookie", "~/.config/pulse/cookie", "~/.pulse-cookie"):
			cookie_path = os.path.expanduser(path)
			if os.path.exists(cookie_path):
				cookie = cookie_path
		
		pulsepath = os.path.join(self.home, ".pulse")
		if not os.path.exists(pulsepath): os.makedirs(pulsepath)
		open(os.path.join(pulsepath, "client.conf"), "w").write(unpad("""
			# Pulseaudio config for sandboxed client
			autospawn = no
			cookie-file = /tmp/pulse-cookie
			enable-shm = no
			auto-connect-localhost = no
			auto-connect-display = no
		"""))
		open(os.path.join(self.home, ".asoundrc"), "w").write(unpad("""
			pcm.pulse { type pulse }
			ctl.pulse { type pulse }
			pcm.!default { type pulse }
			ctl.!default { type pulse }
		"""))
		
		if cookie:
			if verbose:
				print >>sys.stderr, "Copying over", cookie
			(open(os.path.join(self.tmp, "pulse-cookie"), "wb")
					.write(open(cookie, "rb").read()))
		return [
			"--bind", socket, "/tmp/pulse-socket",
			"--setenv", "PULSE_SERVER", "unix:/tmp/pulse-socket"
		]
	
	
	def __repr__(self):
		return "<Sandbox '%s'>" % (self.path, )
	__str__ = __repr__


class Bind(object):
	"""
	Filesystem bind.
	Has type, source in real filesystem, destanation in sanboxed environment and
	can be read-write or read-only.
	"""
	
	FOLDER   = 1	# Normal bind
	OVERLAY  = 2	# Read-only bind with write operations redirected to sandbox data folder
	DEVICE   = 3	# dev-bind mount, allows device access
	DEVTMPFS = 4	# devtmpfs, src is ignored
	PROCFS   = 5	# procfs, src is ignored
	TMPFS    = 6	# tmpfs, src is ignored
	
	def __init__(self, dest, src=None, type=FOLDER, read_write=False, overlay=None):
		self.src = src or dest
		self.dest = dest
		self.overlay = overlay
		self.type = type
		self.read_write = read_write
	
	
	def to_args(self):
		""" Returns arguments for bwrap """
		if self.type == Bind.FOLDER:
			if self.read_write:
				rv = [ "--bind", self.src, self.dest ]
			else:
				rv = [ "--ro-bind", self.src, self.dest ]
			return rv
		elif self.type == Bind.OVERLAY:
			return [ "--bind", self.overlay, self.dest ]
		elif self.type == Bind.DEVICE:
			return [ "--dev-bind", self.src, self.dest ]
		elif self.type == Bind.DEVTMPFS:
			return [ "--dev", self.dest ]
		elif self.type == Bind.PROCFS:
			return [ "--proc", self.dest ]
		elif self.type == Bind.TMPFS:
			return [ "--tmpfs", self.dest ]
		raise TypeError("Invalid Bind type %s" % (self.type, ))


if HAVE_FUSE:
	class sandboxit_overlay(Operations):
		# Class name is visible in 'mount' output, so it doesn't follow
		# normal python class naming
		def __init__(self, readonly, overlay):
			self.readonly = os.path.realpath(readonly)
			self.overlay = os.path.realpath(overlay)
			self._rwlock = Lock()
			self._deleted_path = os.path.join(self.overlay, "_##_deleted_##_")
			try:
				self._deleted = cPickle.load(open(self._deleted_path, "rb"))
			except:
				self._deleted = set(["/_##_deleted_##_"])
		
		def _in_overlay(self, path):
			return os.path.abspath(os.path.join(self.overlay, path.lstrip("/")))
		
		def _in_readonly(self, path):
			return os.path.abspath(os.path.join(self.readonly, path.lstrip("/")))
		
		def _choose(self, path):
			if path in self._deleted:
				raise FuseOSError(ENOENT)
			in_overlay = self._in_overlay(path)
			if os.path.lexists(in_overlay):
				return in_overlay
			return self._in_readonly(path)
		
		def access(self, path, mode):
			path = self._choose(path)
			if not os.access(path, mode):
				raise FuseOSError(EACCES)
		
		def chmod(self, path, mode):
			# Chmod and chown is silently ignored. Throwing error kills `mc`
			pass
		
		def chown(self, path, uid, gid):
			# Chmod and chown is silently ignored. Throwing error kills `mc`
			pass
		
		def create(self, path, mode):
			in_overlay = self._in_overlay(path)
			if path in self._deleted: self._deleted.remove(path)
			self._ensure_parent(in_overlay)
			return os.open(in_overlay, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
		
		def flush(self, path, fh):
			return os.fsync(fh)
		
		def fsync(self, path, datasync, fh):
			return os.fdatasync(fh) if datasync != 0 else os.fsync(fh)
		
		def getattr(self, path, fh=None):
			try:
				path = self._choose(path)
				st = os.lstat(path)
			except Exception, e:
				# print >>sys.stderr, e
				raise
			return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
				'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
		
		getxattr = None
		
		def link(self, target, source):
			raise FuseOSError(EPERM)
		
		listxattr = None
		
		def mkdir(self, path, mode):
			path = self._in_overlay(path)
			if path in self._deleted: self._deleted.remove(path)
			self._ensure_parent(path)
			os.mkdir(path, mode)
		
		def mknod(self, path, mode, dev):
			path = self._in_overlay(path)
			if path in self._deleted: self._deleted.remove(path)
			self._ensure_parent(path)
			os.mknod(path, mode, dev)
		
		def open(self, path, flags):
			if flags & (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_TRUNC) != 0:
				# Opening for appending or _over_writing
				# Make sure file exists in overlay
				in_readonly = self._in_readonly(path)
				path = self._in_overlay(path)
				self._ensure_parent(path)
				if path in self._deleted:
					self._deleted.remove(path)
				elif os.path.lexists(in_readonly) and not os.path.lexists(path):
					file(path, "wb").write(open(in_readonly, "rb").read())
			elif flags & (os.O_CREAT | os.O_TRUNC) != 0:
				# Opening for writing (truncating or new file)
				path = self._in_overlay(path)
				self._ensure_parent(path)
				if path in self._deleted:
					self._deleted.remove(path)
			else:
				# Opening for read-only
				path = self._choose(path)
			try:
				rv = os.open(path, flags)
			except Exception, e:
				# print >>sys.stderr, e
				raise
			return rv
		
		def read(self, path, size, offset, fh):
			with self._rwlock:
				os.lseek(fh, offset, 0)
				return os.read(fh, size)
		
		def readdir(self, path, fh):
			lst = set(['.', '..'])
			in_overlay = self._in_overlay(path)
			in_readonly = self._in_readonly(path)
			if os.path.exists(in_overlay):
				lst.update(os.listdir(in_overlay))
			if os.path.exists(in_readonly):
				lst.update(os.listdir(in_readonly))
			for d in self._deleted:
				if d.startswith(path):
					filename = d[len(path):]
					if filename in lst: lst.remove(filename)
			return lst
		
		def readlink(self, path):
			try:
				return os.readlink(self._choose(path))
			except Exception, e:
				# print >>sys.stderr, e
				raise
		
		def release(self, path, fh):
			return os.close(fh)
		
		def rename(self, old, new):
			in_overlay_old = self._in_overlay(old)
			in_overlay_new = self._in_overlay(new)
			in_readonly_old = self._in_readonly(old)
			if os.path.lexists(in_overlay_old):
				# Renaming overlayed file, easy stuff
				self._ensure_parent(in_overlay_new)
				rv = os.rename(in_overlay_old, in_overlay_new)
			elif os.path.lexists(in_readonly_old):
				# Renaming file from readonly fs is not really posible,
				# so file is copied over
				in_overlay_new_tmp = in_overlay_new + "##tmp"
				self._ensure_parent(in_overlay_new)
				try:
					file(in_overlay_new_tmp, "wb").write(
						file(in_readonly_old, "rb").read())
				except Exception, e:
					print >>sys.stderr, e
					try:
						os.unlink(in_overlay_new_tmp)
					except: pass
					raise e
				rv = os.rename(in_overlay_new_tmp, in_overlay_new)
			else:
				# Renaming non-existing file?
				raise FuseOSError(ENOENT)
			
			if os.path.lexists(in_readonly_old):
				self._deleted.add(old)
				self._save_deleted()
			if new in self._deleted:
				self._deleted.remove(new)
				self._save_deleted()
			return rv
		
		def rmdir(self, path):
			in_overlay = self._in_overlay(path)
			in_readonly = self._in_readonly(path)
			if os.path.exists(in_overlay):
				try:
					os.rmdir(in_overlay)
				except Exception, e:
					print >>sys.stderr, e
					# Dir not empty
					self._deleted.add(path)
					self._save_deleted()
					return
			if os.path.lexists(in_readonly):
				self._deleted.add(path)
				self._save_deleted()
		
		def statfs(self, path):
			path = self._choose(path)
			stv = os.statvfs(path)
			return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
				'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
				'f_frsize', 'f_namemax'))
		
		def symlink(self, target, source):
			target = self._in_overlay(target)
			if target in self._deleted: self._deleted.remove(target)
			self._ensure_parent(target)
			return os.symlink(source, target)
		
		def truncate(self, path, length, fh=None):
			path = self._in_overlay(path)
			if path in self._deleted: self._deleted.remove(path)
			self._ensure_parent(path)
			with open(path, 'r+') as f:
				f.truncate(length)
		
		def unlink(self, path):
			in_overlay = self._in_overlay(path)
			in_readonly = self._in_readonly(path)
			if os.path.lexists(in_overlay):
				os.unlink(in_overlay)
			if os.path.lexists(in_readonly):
				self._deleted.add(path)
				self._save_deleted()
		
		def utimens(self, path, times):
			path = self._in_overlay(path)
			os.utime(path, times)
		
		def write(self, path, data, offset, fh):
			with self._rwlock:
				os.lseek(fh, offset, 0)
				return os.write(fh, data)
		
		def _ensure_parent(self, path):
			"""
			Makes sure that all parent directories of file in overlay are created
			"""
			path = os.path.split(path)[0]
			if not os.path.exists(path): os.makedirs(path)
		
		def _save_deleted(self):
			cPickle.dump(self._deleted, open(self._deleted_path, "wb"))
	
	
	class FuseProcess(object):
		
		def __init__(self, operations, mount_path):
			self.operations = operations
			self.mount_path = mount_path
			self.pid = None
		
		
		def start(self):
			self.pid = os.fork()
			if self.pid == 0:
				# Child process
				FUSE(self.operations, self.mount_path, foreground=True)
				# 'FUSE' blocks until killed
				sys.exit(0)
			else:
				# TODO: Actually wait until filesystem is mounted
				time.sleep(0.5)
		
		
		def umount(self):
			if verbose:
				print >>sys.stderr, "Unmounting", self.mount_path
			try:
				Popen([ "/usr/bin/fusermount", "-uqz", self.mount_path]).communicate()
			except: pass
			try:
				os.path.rmdir(self.mount_path)
			except: pass
			try:
				os.kill(os.pid, 9)
			except: pass


def unpad(text):
	""" Removes initial padding from multiline string """
	return "\n".join(( x.lstrip("\t ") for x in text.split("\n") ))

def is_exe(fpath):
	return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


def find_binary(name):
	"""
	Searchs in PATH and returns full path to binary or None if binary is not found
	"""
	if name.startswith(os.path.sep):
		# Full path, don't search, just check if exists
		if is_exe(name):
			return name
		return None
	
	if os.path.sep in name:
		# relative path, check if exists and return absolute
		path = os.path.abspath(name)
		if is_exe(name):
			return path
		return None
	
	for f in os.environ["PATH"].split(":"):
		path = os.path.join(f, name)
		if is_exe(path):
			return path
	return None


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Runs program sanboxed')
	parser.add_argument('command', type=str, nargs="+", help='command')
	parser.add_argument('-b', '--box', type=str, nargs="?", metavar="box", help='id of sandbox to use')
	parser.add_argument('--for', type=str, metavar="binary", help='execute command in sandbox of another binary')
	parser.add_argument('-n', '--no-net', action="store_true", help='disable network access')
	parser.add_argument('-v', '--verbose', action="store_true", help='be verbose')
	
	if find_binary("bwrap") is None:
		print >>sys.stderr, "bwrap not found. Please, install bubblewrap package"
		sys.exit(1)
	
	args = parser.parse_args()
	verbose = args.verbose
	for_binary = getattr(args, 'for')
	binary, arguments = find_binary(args.command[0]), args.command[1:]
	if binary is None:
		print >>sys.stderr, "%s: %s doesn't exists or is not executable" % (sys.argv[0], args.command[0])
	if for_binary:
		for_binary = find_binary(for_binary)
		sandbox = Sandbox.for_binary(for_binary)
		if verbose:
			print >>sys.stderr, "Entering sandbox of '%s', id '%s'" % (for_binary, sandbox.id)
	elif args.box:
		# TODO: Check sandbox id for weird characters
		sandbox = Sandbox(args.box)
		sandbox.check()
	else:
		sandbox = Sandbox.for_binary(binary)
	if args.no_net:
		sandbox.net = False
	sandbox.execute(binary, arguments)
