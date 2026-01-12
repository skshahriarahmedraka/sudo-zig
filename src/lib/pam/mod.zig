//! PAM (Pluggable Authentication Modules) integration
//!
//! Provides authentication services through PAM:
//! - Starting PAM sessions
//! - Authenticating users
//! - Managing credentials
//! - Session management

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

// Only import PAM headers when PAM is enabled
const c = if (build_options.enable_pam)
    @cImport({
        @cInclude("security/pam_appl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
        @cInclude("stdlib.h");
        @cInclude("string.h");
    })
else
    @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
        @cInclude("stdlib.h");
        @cInclude("string.h");
    });

/// PAM message styles
const PAM_PROMPT_ECHO_OFF = 1;
const PAM_PROMPT_ECHO_ON = 2;
const PAM_ERROR_MSG = 3;
const PAM_TEXT_INFO = 4;

/// PAM flags
const PAM_SILENT = 0x8000;
const PAM_DISALLOW_NULL_AUTHTOK = 0x0001;
const PAM_ESTABLISH_CRED = 0x0002;
const PAM_DELETE_CRED = 0x0004;
const PAM_REINITIALIZE_CRED = 0x0008;
const PAM_REFRESH_CRED = 0x0010;

/// PAM item types
const PAM_SERVICE = 1;
const PAM_USER = 2;
const PAM_TTY = 3;
const PAM_RHOST = 4;
const PAM_CONV = 5;
const PAM_AUTHTOK = 6;
const PAM_OLDAUTHTOK = 7;
const PAM_RUSER = 8;

/// Conversation context passed to PAM callback
const ConversationContext = struct {
    use_stdin: bool = false,
    show_asterisks: bool = false,
    prompt_override: ?[]const u8 = null,
    non_interactive: bool = false,
    bell_on_prompt: bool = false,
};

/// PAM context for managing authentication sessions
pub const PamContext = struct {
    handle: if (build_options.enable_pam) ?*c.pam_handle_t else ?*anyopaque = null,
    service_name: []const u8,
    last_status: c_int = if (build_options.enable_pam) c.PAM_SUCCESS else 0,
    conv_context: ConversationContext,
    session_opened: bool = false,
    creds_established: bool = false,

    // Buffers for null-terminated strings
    _service_buf: [64:0]u8 = undefined,
    _user_buf: [256:0]u8 = undefined,
    _tty_buf: [256:0]u8 = undefined,
    _ruser_buf: [256:0]u8 = undefined,

    const Self = @This();

    /// Initialize a new PAM context
    pub fn init(options: struct {
        service_name: []const u8 = "sudo",
        username: ?[]const u8 = null,
        use_stdin: bool = false,
        show_asterisks: bool = false,
        prompt: ?[]const u8 = null,
        non_interactive: bool = false,
        bell_on_prompt: bool = false,
    }) !Self {
        if (!build_options.enable_pam) {
            return error.PamNotEnabled;
        }

        var self = Self{
            .service_name = options.service_name,
            .conv_context = .{
                .use_stdin = options.use_stdin,
                .show_asterisks = options.show_asterisks,
                .prompt_override = options.prompt,
                .non_interactive = options.non_interactive,
                .bell_on_prompt = options.bell_on_prompt,
            },
        };

        // Copy service name to null-terminated buffer
        if (options.service_name.len >= self._service_buf.len) {
            return error.InvalidArgument;
        }
        @memcpy(self._service_buf[0..options.service_name.len], options.service_name);
        self._service_buf[options.service_name.len] = 0;

        // Prepare username if provided
        var user_ptr: ?[*:0]const u8 = null;
        if (options.username) |name| {
            if (name.len >= self._user_buf.len) {
                return error.InvalidArgument;
            }
            @memcpy(self._user_buf[0..name.len], name);
            self._user_buf[name.len] = 0;
            user_ptr = &self._user_buf;
        }

        // Set up the conversation structure
        // We use a static context pointer - in real usage, we'd need to manage this more carefully
        const conv = c.pam_conv{
            .conv = &pamConversation,
            .appdata_ptr = @ptrCast(&self.conv_context),
        };

        self.last_status = c.pam_start(
            &self._service_buf,
            user_ptr,
            &conv,
            &self.handle,
        );

        if (self.last_status != c.PAM_SUCCESS) {
            return error.PamError;
        }

        return self;
    }

    /// Set the requesting user (PAM_RUSER)
    pub fn setRequestingUser(self: *Self, username: []const u8) !void {
        if (self.handle == null) return error.InvalidState;
        if (username.len >= self._ruser_buf.len) return error.InvalidArgument;

        @memcpy(self._ruser_buf[0..username.len], username);
        self._ruser_buf[username.len] = 0;

        self.last_status = c.pam_set_item(
            self.handle,
            PAM_RUSER,
            @ptrCast(&self._ruser_buf),
        );
        if (self.last_status != c.PAM_SUCCESS) {
            return error.PamError;
        }
    }

    /// Set the TTY (PAM_TTY)
    pub fn setTty(self: *Self, tty: []const u8) !void {
        if (self.handle == null) return error.InvalidState;
        if (tty.len >= self._tty_buf.len) return error.InvalidArgument;

        @memcpy(self._tty_buf[0..tty.len], tty);
        self._tty_buf[tty.len] = 0;

        self.last_status = c.pam_set_item(
            self.handle,
            PAM_TTY,
            @ptrCast(&self._tty_buf),
        );
        if (self.last_status != c.PAM_SUCCESS) {
            return error.PamError;
        }
    }

    /// Authenticate the user
    pub fn authenticate(self: *Self, flags: u32) !void {
        if (self.handle == null) return error.InvalidState;

        var pam_flags: c_int = 0;
        if (flags & AUTH_SILENT != 0) pam_flags |= PAM_SILENT;
        if (flags & AUTH_DISALLOW_NULL != 0) pam_flags |= PAM_DISALLOW_NULL_AUTHTOK;

        self.last_status = c.pam_authenticate(self.handle, pam_flags);

        switch (self.last_status) {
            c.PAM_SUCCESS => return,
            c.PAM_AUTH_ERR => return error.AuthenticationFailed,
            c.PAM_MAXTRIES => return error.MaxAuthAttempts,
            c.PAM_USER_UNKNOWN => return error.UserNotFound,
            c.PAM_CRED_INSUFFICIENT => return error.CredentialError,
            c.PAM_AUTHINFO_UNAVAIL => return error.ServiceUnavailable,
            c.PAM_ABORT => return error.Aborted,
            else => return error.PamError,
        }
    }

    /// Validate the account (check expiration, access restrictions, etc.)
    pub fn validateAccount(self: *Self) !void {
        if (self.handle == null) return error.InvalidState;

        self.last_status = c.pam_acct_mgmt(self.handle, 0);

        switch (self.last_status) {
            c.PAM_SUCCESS => return,
            c.PAM_ACCT_EXPIRED => return error.AccountExpired,
            c.PAM_NEW_AUTHTOK_REQD => return error.PasswordChangeRequired,
            c.PAM_PERM_DENIED => return error.PermissionDenied,
            c.PAM_USER_UNKNOWN => return error.UserNotFound,
            else => return error.PamError,
        }
    }

    /// Establish credentials
    pub fn establishCredentials(self: *Self) !void {
        if (self.handle == null) return error.InvalidState;

        self.last_status = c.pam_setcred(self.handle, PAM_ESTABLISH_CRED);
        if (self.last_status != c.PAM_SUCCESS) {
            return error.CredentialError;
        }
        self.creds_established = true;
    }

    /// Refresh credentials
    pub fn refreshCredentials(self: *Self) !void {
        if (self.handle == null) return error.InvalidState;

        self.last_status = c.pam_setcred(self.handle, PAM_REFRESH_CRED);
        if (self.last_status != c.PAM_SUCCESS) {
            return error.CredentialError;
        }
    }

    /// Open a PAM session
    pub fn openSession(self: *Self) !void {
        if (self.handle == null) return error.InvalidState;

        self.last_status = c.pam_open_session(self.handle, 0);
        if (self.last_status != c.PAM_SUCCESS) {
            return error.SessionError;
        }
        self.session_opened = true;
    }

    /// Close the PAM session
    pub fn closeSession(self: *Self) void {
        if (self.handle) |h| {
            if (self.session_opened) {
                _ = c.pam_close_session(h, 0);
                self.session_opened = false;
            }
        }
    }

    /// Delete credentials
    pub fn deleteCredentials(self: *Self) void {
        if (self.handle) |h| {
            if (self.creds_established) {
                _ = c.pam_setcred(h, PAM_DELETE_CRED);
                self.creds_established = false;
            }
        }
    }

    /// Get environment variables set by PAM modules
    pub fn getEnv(self: *Self, allocator: std.mem.Allocator) !std.StringHashMap([]const u8) {
        var env_map = std.StringHashMap([]const u8).init(allocator);
        errdefer env_map.deinit();

        if (self.handle) |h| {
            const envlist = c.pam_getenvlist(h);
            if (envlist != null) {
                var i: usize = 0;
                while (envlist[i] != null) : (i += 1) {
                    const entry = std.mem.span(envlist[i].?);
                    if (std.mem.indexOf(u8, entry, "=")) |eq_pos| {
                        const key = try allocator.dupe(u8, entry[0..eq_pos]);
                        const value = try allocator.dupe(u8, entry[eq_pos + 1 ..]);
                        try env_map.put(key, value);
                    }
                }
            }
        }

        return env_map;
    }

    /// End the PAM transaction
    pub fn deinit(self: *Self) void {
        self.closeSession();
        self.deleteCredentials();

        if (self.handle) |h| {
            _ = c.pam_end(h, self.last_status);
            self.handle = null;
        }
    }

    /// Get error message for last error
    pub fn errorMessage(self: Self) []const u8 {
        if (self.handle) |h| {
            const msg = c.pam_strerror(h, self.last_status);
            if (msg != null) {
                return std.mem.span(msg);
            }
        }
        return "Unknown PAM error";
    }

    // Authentication flags
    pub const AUTH_SILENT: u32 = 1;
    pub const AUTH_DISALLOW_NULL: u32 = 2;
};

/// PAM conversation callback function
fn pamConversation(
    num_msg: c_int,
    msg: [*c][*c]const c.pam_message,
    resp: [*c][*c]c.pam_response,
    appdata_ptr: ?*anyopaque,
) callconv(.c) c_int {
    const ctx: *const ConversationContext = if (appdata_ptr) |ptr|
        @ptrCast(@alignCast(ptr))
    else
        return c.PAM_CONV_ERR;

    // Allocate response array
    const responses = @as([*c]c.pam_response, @ptrCast(@alignCast(c.calloc(
        @intCast(num_msg),
        @sizeOf(c.pam_response),
    ) orelse return c.PAM_BUF_ERR)));

    var i: usize = 0;
    while (i < @as(usize, @intCast(num_msg))) : (i += 1) {
        const m = msg[i].*;
        const msg_style = m.msg_style;

        switch (msg_style) {
            PAM_PROMPT_ECHO_OFF => {
                // Password prompt - read without echo
                if (ctx.non_interactive) {
                    c.free(responses);
                    return c.PAM_CONV_ERR;
                }

                const prompt = if (ctx.prompt_override) |p|
                    p
                else if (m.msg != null)
                    std.mem.span(m.msg)
                else
                    "Password: ";

                const password = readPassword(prompt, ctx.use_stdin, ctx.show_asterisks, ctx.bell_on_prompt) catch {
                    c.free(responses);
                    return c.PAM_CONV_ERR;
                };

                // PAM expects malloc'd string it will free
                const pwd_copy = c.strdup(password.ptr) orelse {
                    c.free(responses);
                    return c.PAM_BUF_ERR;
                };
                responses[i].resp = pwd_copy;
                responses[i].resp_retcode = 0;
            },
            PAM_PROMPT_ECHO_ON => {
                // Prompt with echo (e.g., username)
                if (ctx.non_interactive) {
                    c.free(responses);
                    return c.PAM_CONV_ERR;
                }

                const prompt = if (m.msg != null)
                    std.mem.span(m.msg)
                else
                    "";

                _ = std.posix.write(std.posix.STDERR_FILENO, prompt) catch {};

                var buf: [256]u8 = undefined;
                const input = readLine(ctx.use_stdin, &buf) catch {
                    c.free(responses);
                    return c.PAM_CONV_ERR;
                };

                const input_copy = c.strndup(input.ptr, input.len) orelse {
                    c.free(responses);
                    return c.PAM_BUF_ERR;
                };
                responses[i].resp = input_copy;
                responses[i].resp_retcode = 0;
            },
            PAM_ERROR_MSG => {
                // Error message - display to user
                if (m.msg != null) {
                    const error_msg = std.mem.span(m.msg);
                    _ = std.posix.write(std.posix.STDERR_FILENO, error_msg) catch {};
                    _ = std.posix.write(std.posix.STDERR_FILENO, "\n") catch {};
                }
                responses[i].resp = null;
                responses[i].resp_retcode = 0;
            },
            PAM_TEXT_INFO => {
                // Informational message - display to user
                if (m.msg != null) {
                    const info_msg = std.mem.span(m.msg);
                    _ = std.posix.write(std.posix.STDOUT_FILENO, info_msg) catch {};
                    _ = std.posix.write(std.posix.STDOUT_FILENO, "\n") catch {};
                }
                responses[i].resp = null;
                responses[i].resp_retcode = 0;
            },
            else => {
                c.free(responses);
                return c.PAM_CONV_ERR;
            },
        }
    }

    resp.* = responses;
    return c.PAM_SUCCESS;
}

/// Read a password from the terminal with echo disabled
pub fn readPassword(prompt: []const u8, use_stdin: bool, show_asterisks: bool, bell: bool) ![:0]const u8 {
    const fd = if (use_stdin) std.posix.STDIN_FILENO else blk: {
        // Try to open /dev/tty for direct terminal access
        const tty_fd = std.posix.open("/dev/tty", .{ .ACCMODE = .RDWR }, 0) catch {
            break :blk std.posix.STDIN_FILENO;
        };
        break :blk tty_fd;
    };
    defer if (fd != std.posix.STDIN_FILENO) std.posix.close(fd);

    const output_fd = if (use_stdin) std.posix.STDERR_FILENO else fd;

    // Ring bell if requested
    if (bell) {
        _ = std.posix.write(output_fd, "\x07") catch {}; // BEL character
    }

    // Write prompt
    _ = std.posix.write(output_fd, prompt) catch {};

    // Save terminal settings and disable echo
    var orig_termios: c.termios = undefined;
    const have_termios = c.tcgetattr(fd, &orig_termios) == 0;

    if (have_termios) {
        var new_termios = orig_termios;
        new_termios.c_lflag &= ~@as(c_uint, c.ECHO);
        if (!show_asterisks) {
            new_termios.c_lflag &= ~@as(c_uint, c.ICANON);
        }
        _ = c.tcsetattr(fd, c.TCSANOW, &new_termios);
    }

    defer {
        if (have_termios) {
            _ = c.tcsetattr(fd, c.TCSANOW, &orig_termios);
        }
        // Print newline after password
        _ = std.posix.write(output_fd, "\n") catch {};
    }

    // Read password
    var password_buf: [256:0]u8 = undefined;
    var len: usize = 0;

    if (show_asterisks and have_termios) {
        // Read character by character, showing asterisks
        while (len < password_buf.len - 1) {
            var char_buf: [1]u8 = undefined;
            const n = std.posix.read(fd, &char_buf) catch break;
            if (n == 0) break;

            const char = char_buf[0];
            if (char == '\n' or char == '\r') break;
            if (char == 127 or char == 8) {
                // Backspace
                if (len > 0) {
                    len -= 1;
                    _ = std.posix.write(output_fd, "\x08 \x08") catch {}; // Erase asterisk
                }
                continue;
            }
            if (char < 32) continue; // Ignore control characters

            password_buf[len] = char;
            len += 1;
            _ = std.posix.write(output_fd, "*") catch {};
        }
    } else {
        // Read line normally
        var buf: [256]u8 = undefined;
        const line = readLineFromFd(fd, &buf) catch return error.ReadError;
        @memcpy(password_buf[0..line.len], line);
        len = line.len;
    }

    password_buf[len] = 0;
    return password_buf[0..len :0];
}

/// Read a line of input
fn readLine(use_stdin: bool, buf: []u8) ![]const u8 {
    const fd = if (use_stdin) std.posix.STDIN_FILENO else std.posix.STDIN_FILENO;
    return readLineFromFd(fd, buf);
}

/// Read a line from a file descriptor
fn readLineFromFd(fd: std.posix.fd_t, buf: []u8) ![]const u8 {
    var len: usize = 0;
    while (len < buf.len) {
        var char_buf: [1]u8 = undefined;
        const n = std.posix.read(fd, &char_buf) catch |err| {
            if (len > 0) return buf[0..len];
            return err;
        };
        if (n == 0) break;
        if (char_buf[0] == '\n') break;
        buf[len] = char_buf[0];
        len += 1;
    }
    return buf[0..len];
}

/// Perform full authentication flow for sudo
pub fn authenticateUser(options: struct {
    service: []const u8 = "sudo",
    username: []const u8,
    requesting_user: []const u8,
    tty: ?[]const u8 = null,
    use_stdin: bool = false,
    show_asterisks: bool = false,
    prompt: ?[]const u8 = null,
    non_interactive: bool = false,
}) !void {
    if (!build_options.enable_pam) {
        return; // Skip authentication if PAM is not enabled
    }

    var pam = try PamContext.init(.{
        .service_name = options.service,
        .username = options.username,
        .use_stdin = options.use_stdin,
        .show_asterisks = options.show_asterisks,
        .prompt = options.prompt,
        .non_interactive = options.non_interactive,
    });
    defer pam.deinit();

    // Set requesting user
    try pam.setRequestingUser(options.requesting_user);

    // Set TTY if available
    if (options.tty) |tty| {
        try pam.setTty(tty);
    }

    // Authenticate
    try pam.authenticate(PamContext.AUTH_DISALLOW_NULL);

    // Validate account
    try pam.validateAccount();

    // Establish credentials
    try pam.establishCredentials();
}

/// PAM error types
pub const PamError = error{
    PamError,
    PamNotEnabled,
    AuthenticationFailed,
    MaxAuthAttempts,
    AccountExpired,
    PasswordChangeRequired,
    CredentialError,
    SessionError,
    PermissionDenied,
    ServiceUnavailable,
    UserNotFound,
    InvalidState,
    InvalidArgument,
    ReadError,
    Aborted,
};

test {
    // PAM tests require system configuration, skip in unit tests
    // Just verify the module compiles
    _ = PamContext;
    _ = ConversationContext;
}
