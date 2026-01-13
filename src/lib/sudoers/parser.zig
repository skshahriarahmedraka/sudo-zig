//! Sudoers file parser
//!
//! This module parses sudoers files into an AST representation.

const std = @import("std");
const Allocator = std.mem.Allocator;
const tokens = @import("tokens.zig");
const ast = @import("ast.zig");

const Token = tokens.Token;
const TokenType = tokens.TokenType;
const Tokenizer = tokens.Tokenizer;

/// Parse error with location information
pub const ParseError = struct {
    message: []const u8,
    line: u32,
    column: u32,
    token_lexeme: []const u8 = "",

    /// Format the error for display
    pub fn format(self: ParseError, writer: anytype) !void {
        try writer.print("sudoers:{d}:{d}: error: {s}", .{
            self.line,
            self.column,
            self.message,
        });
        if (self.token_lexeme.len > 0) {
            try writer.print(" (near '{s}')", .{self.token_lexeme});
        }
    }

    /// Convert to a displayable string
    pub fn toString(self: ParseError, buf: []u8) []const u8 {
        var stream = std.io.fixedBufferStream(buf);
        self.format(stream.writer()) catch return "error formatting parse error";
        return stream.getWritten();
    }
};

/// Parser for sudoers files
pub const Parser = struct {
    allocator: Allocator,
    tokenizer: Tokenizer,
    current: Token,
    previous: Token,
    errors: std.ArrayListUnmanaged(ParseError),
    had_error: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, source: []const u8) Self {
        var tokenizer = Tokenizer.init(source);
        const first_token = tokenizer.next();
        return .{
            .allocator = allocator,
            .tokenizer = tokenizer,
            .current = first_token,
            .previous = first_token,
            .errors = .{},
            .had_error = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.errors.deinit(self.allocator);
    }

    pub fn parse(self: *Self) !ast.Sudoers {
        var sudoers = ast.Sudoers.init(self.allocator);
        errdefer sudoers.deinit();

        while (!self.isAtEnd()) {
            self.skipNewlinesAndComments();
            if (self.isAtEnd()) break;

            if (self.parseStatement(&sudoers)) |_| {} else |err| {
                if (err == error.ParseError) {
                    self.synchronize();
                } else {
                    return err;
                }
            }
        }

        if (self.had_error) return error.ParseError;
        return sudoers;
    }

    fn parseStatement(self: *Self, sudoers: *ast.Sudoers) !void {
        switch (self.current.type) {
            .keyword_defaults => try self.parseDefaults(sudoers),
            .keyword_user_alias => try self.parseUserAlias(sudoers),
            .keyword_host_alias => try self.parseHostAlias(sudoers),
            .keyword_cmnd_alias => try self.parseCmndAlias(sudoers),
            .keyword_runas_alias => try self.parseRunasAlias(sudoers),
            .keyword_include => try self.parseInclude(sudoers, false),
            .keyword_includedir => try self.parseInclude(sudoers, true),
            else => try self.parseUserSpec(sudoers),
        }
    }

    fn parseInclude(self: *Self, sudoers: *ast.Sudoers, is_directory: bool) !void {
        _ = self.advance(); // consume @include or @includedir

        // Get the path - can be a command_path or quoted_string
        var path: []const u8 = "";
        if (self.check(.command_path)) {
            path = self.current.lexeme;
            _ = self.advance();
        } else if (self.check(.quoted_string)) {
            const quoted = self.current.lexeme;
            _ = self.advance();
            // Remove quotes
            if (quoted.len >= 2) {
                path = quoted[1 .. quoted.len - 1];
            }
        } else if (self.check(.identifier)) {
            path = self.current.lexeme;
            _ = self.advance();
        } else {
            return self.errorAtCurrent("Expected path after include directive");
        }

        try sudoers.addInclude(.{
            .path = path,
            .is_directory = is_directory,
        });

        self.skipToEndOfLine();
    }

    fn parseDefaults(self: *Self, sudoers: *ast.Sudoers) !void {
        _ = self.advance(); // consume 'Defaults'
        var default = ast.Default.init("");

        // Check for scope specifier: Defaults:user, Defaults@host, Defaults!cmnd, Defaults>runas
        if (self.check(.colon)) {
            _ = self.advance(); // consume ':'
            // User scope - parse user list
            if (self.check(.identifier) or self.check(.all) or self.check(.groupname) or self.check(.uid) or self.check(.bang)) {
                const user_list = try self.parseUserList();
                default.scope = .{ .user_list = user_list };
            } else {
                return self.errorAtCurrent("Expected user specification after 'Defaults:'");
            }
        } else if (self.check(.identifier)) {
            // Check if the identifier starts with @ (host scope) encoded in lexeme
            // Actually, we need to check for special prefix characters
            const lexeme = self.current.lexeme;
            if (lexeme.len > 0) {
                // Check next char after Defaults for @, !, >
                // These are parsed as part of the identifier by the tokenizer in some cases
                // For proper handling, we need to check the raw source
            }
        }

        // Parse the actual default settings (can be multiple comma-separated)
        while (true) {
            var setting_default = ast.Default.init("");
            setting_default.scope = default.scope;

            if (self.match(.bang)) {
                setting_default.operator = .negate;
            }

            if (!self.check(.identifier)) {
                if (self.check(.newline) or self.check(.eof)) break;
                return self.errorAtCurrent("Expected setting name");
            }

            setting_default.name = self.current.lexeme;
            _ = self.advance();

            if (self.match(.equals)) {
                setting_default.operator = if (setting_default.operator == .negate) .negate else .set;
                setting_default.value = try self.parseDefaultValue();
            } else if (self.match(.plus_equals)) {
                setting_default.operator = .add;
                setting_default.value = try self.parseDefaultValue();
            } else if (self.match(.minus_equals)) {
                setting_default.operator = .remove;
                setting_default.value = try self.parseDefaultValue();
            }

            try sudoers.addDefault(setting_default);

            // Check for comma (multiple settings on same line)
            if (!self.match(.comma)) break;
        }

        self.skipToEndOfLine();
    }

    fn parseDefaultValue(self: *Self) !?ast.DefaultValue {
        if (self.check(.quoted_string)) {
            const value = self.current.lexeme;
            _ = self.advance();
            if (value.len >= 2) {
                return .{ .string = value[1 .. value.len - 1] };
            }
            return .{ .string = value };
        } else if (self.check(.identifier)) {
            const value = self.current.lexeme;
            _ = self.advance();
            if (std.fmt.parseInt(i64, value, 10)) |int_val| {
                return .{ .integer = int_val };
            } else |_| {
                return .{ .string = value };
            }
        }
        return null;
    }

    fn parseUserAlias(self: *Self, sudoers: *ast.Sudoers) !void {
        _ = self.advance();
        while (true) {
            if (!self.check(.identifier)) return self.errorAtCurrent("Expected alias name");
            const name = self.current.lexeme;
            _ = self.advance();
            if (!self.match(.equals)) return self.errorAtCurrent("Expected '='");
            const members = try self.parseUserList();
            try sudoers.aliases.addUserAlias(name, members);
            if (!self.match(.colon)) break;
        }
        self.skipToEndOfLine();
    }

    fn parseHostAlias(self: *Self, sudoers: *ast.Sudoers) !void {
        _ = self.advance();
        while (true) {
            if (!self.check(.identifier)) return self.errorAtCurrent("Expected alias name");
            const name = self.current.lexeme;
            _ = self.advance();
            if (!self.match(.equals)) return self.errorAtCurrent("Expected '='");
            const members = try self.parseHostList();
            try sudoers.aliases.addHostAlias(name, members);
            if (!self.match(.colon)) break;
        }
        self.skipToEndOfLine();
    }

    fn parseCmndAlias(self: *Self, sudoers: *ast.Sudoers) !void {
        _ = self.advance();
        while (true) {
            if (!self.check(.identifier)) return self.errorAtCurrent("Expected alias name");
            const name = self.current.lexeme;
            _ = self.advance();
            if (!self.match(.equals)) return self.errorAtCurrent("Expected '='");
            const members = try self.parseCmndList();
            try sudoers.aliases.addCmndAlias(name, members);
            if (!self.match(.colon)) break;
        }
        self.skipToEndOfLine();
    }

    fn parseRunasAlias(self: *Self, sudoers: *ast.Sudoers) !void {
        _ = self.advance();
        while (true) {
            if (!self.check(.identifier)) return self.errorAtCurrent("Expected alias name");
            const name = self.current.lexeme;
            _ = self.advance();
            if (!self.match(.equals)) return self.errorAtCurrent("Expected '='");
            const members = try self.parseRunasList();
            try sudoers.aliases.addRunasAlias(name, members);
            if (!self.match(.colon)) break;
        }
        self.skipToEndOfLine();
    }

    fn parseUserSpec(self: *Self, sudoers: *ast.Sudoers) !void {
        const users = try self.parseUserList();
        var spec = ast.UserSpec.init(self.allocator, users);
        errdefer spec.deinit(self.allocator);

        while (true) {
            const host_spec = try self.parseHostSpec();
            try spec.addHostSpec(host_spec);
            if (self.check(.newline) or self.check(.eof)) break;
        }

        try sudoers.addUserSpec(spec);
    }

    fn parseHostSpec(self: *Self) !ast.HostSpec {
        const hosts = try self.parseHostList();
        var host_spec = ast.HostSpec.init(self.allocator, hosts);
        errdefer host_spec.deinit(self.allocator);

        if (!self.match(.equals)) return self.errorAtCurrent("Expected '='");

        while (true) {
            const cmnd_spec = try self.parseCmndSpec();
            try host_spec.addCmndSpec(cmnd_spec);
            if (!self.match(.comma)) break;
            if (self.check(.newline) or self.check(.eof)) break;
        }

        return host_spec;
    }

    fn parseCmndSpec(self: *Self) !ast.CmndSpec {
        var cmnd_spec = ast.CmndSpec.init(ast.CmndList.init(self.allocator));
        errdefer cmnd_spec.deinit(self.allocator);

        if (self.check(.open_paren)) {
            cmnd_spec.runas = try self.parseRunAs();
        }

        cmnd_spec.tags = self.parseTags();
        cmnd_spec.commands = try self.parseCmndList();
        return cmnd_spec;
    }

    fn parseRunAs(self: *Self) !ast.RunAs {
        _ = self.advance();
        var runas = ast.RunAs.init();
        errdefer runas.deinit(self.allocator);

        if (!self.check(.colon) and !self.check(.close_paren)) {
            var users = ast.UserList.init(self.allocator);
            errdefer users.deinit(self.allocator);
            while (true) {
                const item = try self.parseUserItem();
                try users.append(self.allocator, item);
                if (!self.match(.comma)) break;
                if (self.check(.colon) or self.check(.close_paren)) break;
            }
            runas.users = users;
        }

        if (self.match(.colon)) {
            if (!self.check(.close_paren)) {
                var groups = ast.GroupList.init(self.allocator);
                errdefer groups.deinit(self.allocator);
                while (true) {
                    const item = try self.parseGroupItem();
                    try groups.append(self.allocator, item);
                    if (!self.match(.comma)) break;
                    if (self.check(.close_paren)) break;
                }
                runas.groups = groups;
            }
        }

        if (!self.match(.close_paren)) return self.errorAtCurrent("Expected ')'");
        return runas;
    }

    fn parseTags(self: *Self) ast.Tags {
        var tags = ast.Tags{};
        while (true) {
            switch (self.current.type) {
                .tag_passwd => { tags.passwd = true; _ = self.advance(); _ = self.match(.colon); },
                .tag_nopasswd => { tags.passwd = false; _ = self.advance(); _ = self.match(.colon); },
                .tag_setenv => { tags.setenv = true; _ = self.advance(); _ = self.match(.colon); },
                .tag_nosetenv => { tags.setenv = false; _ = self.advance(); _ = self.match(.colon); },
                .tag_exec => { tags.noexec = false; _ = self.advance(); _ = self.match(.colon); },
                .tag_noexec => { tags.noexec = true; _ = self.advance(); _ = self.match(.colon); },
                .tag_log_input => { tags.log_input = true; _ = self.advance(); _ = self.match(.colon); },
                .tag_nolog_input => { tags.log_input = false; _ = self.advance(); _ = self.match(.colon); },
                .tag_log_output => { tags.log_output = true; _ = self.advance(); _ = self.match(.colon); },
                .tag_nolog_output => { tags.log_output = false; _ = self.advance(); _ = self.match(.colon); },
                else => break,
            }
        }
        return tags;
    }

    fn parseUserList(self: *Self) !ast.UserList {
        var list = ast.UserList.init(self.allocator);
        errdefer list.deinit(self.allocator);
        while (true) {
            const item = try self.parseUserItem();
            try list.append(self.allocator, item);
            if (!self.match(.comma)) break;
        }
        return list;
    }

    fn parseUserItem(self: *Self) !ast.UserItem {
        var negated = false;
        if (self.match(.bang)) negated = true;
        const value = try self.parseUserValue();
        return .{ .negated = negated, .value = value };
    }

    fn parseUserValue(self: *Self) !ast.UserValue {
        switch (self.current.type) {
            .all => { _ = self.advance(); return .{ .all = {} }; },
            .identifier => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (isAllUppercase(name)) return .{ .alias = name };
                return .{ .username = name };
            },
            .groupname => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 1) return .{ .groupname = name[1..] };
                return .{ .groupname = name };
            },
            .uid => {
                const lexeme = self.current.lexeme;
                _ = self.advance();
                if (lexeme.len > 1) {
                    const uid = std.fmt.parseInt(u32, lexeme[1..], 10) catch 0;
                    return .{ .uid = uid };
                }
                return .{ .uid = 0 };
            },
            .gid => {
                const lexeme = self.current.lexeme;
                _ = self.advance();
                if (lexeme.len > 2) {
                    const gid = std.fmt.parseInt(u32, lexeme[2..], 10) catch 0;
                    return .{ .gid = gid };
                }
                return .{ .gid = 0 };
            },
            .netgroup => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 1) return .{ .netgroup = name[1..] };
                return .{ .netgroup = name };
            },
            .non_unix_group => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 2) return .{ .non_unix_group = name[2..] };
                return .{ .non_unix_group = name };
            },
            .non_unix_gid => {
                const lexeme = self.current.lexeme;
                _ = self.advance();
                if (lexeme.len > 3) {
                    const gid = std.fmt.parseInt(u32, lexeme[3..], 10) catch 0;
                    return .{ .non_unix_gid = gid };
                }
                return .{ .non_unix_gid = 0 };
            },
            else => return self.errorAtCurrent("Expected user specification"),
        }
    }

    fn parseHostList(self: *Self) !ast.HostList {
        var list = ast.HostList.init(self.allocator);
        errdefer list.deinit(self.allocator);
        while (true) {
            const item = try self.parseHostItem();
            try list.append(self.allocator, item);
            if (!self.match(.comma)) break;
            if (self.check(.equals)) break;
        }
        return list;
    }

    fn parseHostItem(self: *Self) !ast.HostItem {
        var negated = false;
        if (self.match(.bang)) negated = true;
        const value = try self.parseHostValue();
        return .{ .negated = negated, .value = value };
    }

    fn parseHostValue(self: *Self) !ast.HostValue {
        switch (self.current.type) {
            .all => { _ = self.advance(); return .{ .all = {} }; },
            .identifier => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (isAllUppercase(name)) return .{ .alias = name };
                if (looksLikeIpAddress(name)) {
                    if (std.mem.indexOf(u8, name, "/")) |_| return .{ .ip_network = name };
                    return .{ .ip_addr = name };
                }
                return .{ .hostname = name };
            },
            .netgroup => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 1) return .{ .netgroup = name[1..] };
                return .{ .netgroup = name };
            },
            else => return self.errorAtCurrent("Expected host specification"),
        }
    }

    fn parseCmndList(self: *Self) !ast.CmndList {
        var list = ast.CmndList.init(self.allocator);
        errdefer list.deinit(self.allocator);
        while (true) {
            const item = try self.parseCmndItem();
            try list.append(self.allocator, item);
            if (!self.match(.comma)) break;
            if (self.check(.newline) or self.check(.eof)) break;
            if (self.check(.open_paren) or self.isTag()) break;
        }
        return list;
    }

    fn parseCmndItem(self: *Self) !ast.CmndItem {
        var negated = false;
        if (self.match(.bang)) negated = true;
        const value = try self.parseCmndValue();
        return .{ .negated = negated, .value = value };
    }

    fn parseCmndValue(self: *Self) !ast.CmndValue {
        // Check for SHA digest prefix: sha256:HASH /path/to/cmd
        var digest: ?ast.Digest = null;
        if (self.current.type == .sha224 or self.current.type == .sha256 or
            self.current.type == .sha384 or self.current.type == .sha512)
        {
            const algorithm: ast.DigestAlgorithm = switch (self.current.type) {
                .sha224 => .sha224,
                .sha256 => .sha256,
                .sha384 => .sha384,
                .sha512 => .sha512,
                else => unreachable,
            };
            _ = self.advance(); // consume algorithm name

            if (!self.match(.colon)) {
                return self.errorAtCurrent("Expected ':' after digest algorithm");
            }

            // The hash should be the next identifier
            if (!self.check(.identifier)) {
                return self.errorAtCurrent("Expected hash value after digest algorithm");
            }
            const hash = self.current.lexeme;
            _ = self.advance();

            digest = .{
                .algorithm = algorithm,
                .hash = hash,
            };
        }

        switch (self.current.type) {
            .all => { _ = self.advance(); return .{ .all = {} }; },
            .command_path => {
                const path = self.current.lexeme;
                _ = self.advance();
                if (std.mem.eql(u8, path, "sudoedit")) {
                    var args: ?[]const u8 = null;
                    if (self.check(.identifier) or self.check(.command_path)) {
                        args = self.current.lexeme;
                        _ = self.advance();
                    }
                    return .{ .sudoedit = args orelse "" };
                }
                var cmd = ast.Command.init(path);
                cmd.digest = digest;
                // Parse command arguments - can be identifier, quoted_string, or wildcard *
                if (self.check(.identifier) or self.check(.quoted_string)) {
                    cmd.args = self.current.lexeme;
                    _ = self.advance();
                } else if (self.check(.all)) {
                    // ALL after command means any arguments - but this is unusual
                    // Usually * is used for wildcard args, but the tokenizer may not handle it
                }
                return .{ .command = cmd };
            },
            .identifier => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (isAllUppercase(name)) return .{ .alias = name };
                if (std.mem.eql(u8, name, "sudoedit")) {
                    var args: ?[]const u8 = null;
                    if (self.check(.command_path)) {
                        args = self.current.lexeme;
                        _ = self.advance();
                    }
                    return .{ .sudoedit = args orelse "" };
                }
                return .{ .alias = name };
            },
            else => return self.errorAtCurrent("Expected command specification"),
        }
    }

    fn parseGroupItem(self: *Self) !ast.GroupItem {
        var negated = false;
        if (self.match(.bang)) negated = true;
        const value = try self.parseGroupValue();
        return .{ .negated = negated, .value = value };
    }

    fn parseGroupValue(self: *Self) !ast.GroupValue {
        switch (self.current.type) {
            .all => { _ = self.advance(); return .{ .all = {} }; },
            .identifier => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (isAllUppercase(name)) return .{ .alias = name };
                return .{ .groupname = name };
            },
            .groupname => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 1) return .{ .groupname = name[1..] };
                return .{ .groupname = name };
            },
            .gid, .uid => {
                const lexeme = self.current.lexeme;
                _ = self.advance();
                if (lexeme.len > 1) {
                    const gid = std.fmt.parseInt(u32, lexeme[1..], 10) catch 0;
                    return .{ .gid = gid };
                }
                return .{ .gid = 0 };
            },
            .non_unix_group => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 2) return .{ .non_unix_group = name[2..] };
                return .{ .non_unix_group = name };
            },
            .non_unix_gid => {
                const lexeme = self.current.lexeme;
                _ = self.advance();
                if (lexeme.len > 3) {
                    const gid = std.fmt.parseInt(u32, lexeme[3..], 10) catch 0;
                    return .{ .non_unix_gid = gid };
                }
                return .{ .non_unix_gid = 0 };
            },
            else => return self.errorAtCurrent("Expected group specification"),
        }
    }

    fn parseRunasList(self: *Self) !ast.RunasList {
        var list = ast.RunasList.init(self.allocator);
        errdefer list.deinit(self.allocator);
        while (true) {
            const item = try self.parseRunasItem();
            try list.append(self.allocator, item);
            if (!self.match(.comma)) break;
        }
        return list;
    }

    fn parseRunasItem(self: *Self) !ast.RunasItem {
        var negated = false;
        if (self.match(.bang)) negated = true;
        const value = try self.parseRunasValue();
        return .{ .negated = negated, .value = value };
    }

    fn parseRunasValue(self: *Self) !ast.RunasValue {
        switch (self.current.type) {
            .all => { _ = self.advance(); return .{ .all = {} }; },
            .identifier => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (isAllUppercase(name)) return .{ .alias = name };
                return .{ .username = name };
            },
            .groupname => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 1) return .{ .groupname = name[1..] };
                return .{ .groupname = name };
            },
            .uid => {
                const lexeme = self.current.lexeme;
                _ = self.advance();
                if (lexeme.len > 1) {
                    const uid = std.fmt.parseInt(u32, lexeme[1..], 10) catch 0;
                    return .{ .uid = uid };
                }
                return .{ .uid = 0 };
            },
            .gid => {
                const lexeme = self.current.lexeme;
                _ = self.advance();
                if (lexeme.len > 2) {
                    const gid = std.fmt.parseInt(u32, lexeme[2..], 10) catch 0;
                    return .{ .gid = gid };
                }
                return .{ .gid = 0 };
            },
            .netgroup => {
                const name = self.current.lexeme;
                _ = self.advance();
                if (name.len > 1) return .{ .netgroup = name[1..] };
                return .{ .netgroup = name };
            },
            else => return self.errorAtCurrent("Expected RunAs specification"),
        }
    }

    fn advance(self: *Self) Token {
        self.previous = self.current;
        self.current = self.tokenizer.next();
        return self.previous;
    }

    fn check(self: *Self, token_type: TokenType) bool {
        return self.current.type == token_type;
    }

    fn match(self: *Self, token_type: TokenType) bool {
        if (!self.check(token_type)) return false;
        _ = self.advance();
        return true;
    }

    fn isAtEnd(self: *Self) bool {
        return self.current.type == .eof;
    }

    fn isTag(self: *Self) bool {
        return switch (self.current.type) {
            .tag_passwd, .tag_nopasswd, .tag_setenv, .tag_nosetenv, .tag_exec, .tag_noexec, .tag_log_input, .tag_nolog_input, .tag_log_output, .tag_nolog_output => true,
            else => false,
        };
    }

    fn skipNewlinesAndComments(self: *Self) void {
        while (self.current.type == .newline or self.current.type == .comment) {
            _ = self.advance();
        }
    }

    fn skipToEndOfLine(self: *Self) void {
        while (!self.isAtEnd() and self.current.type != .newline) {
            _ = self.advance();
        }
        if (self.current.type == .newline) _ = self.advance();
    }

    fn synchronize(self: *Self) void {
        while (!self.isAtEnd()) {
            if (self.previous.type == .newline) return;
            switch (self.current.type) {
                .keyword_defaults, .keyword_user_alias, .keyword_host_alias, .keyword_cmnd_alias, .keyword_runas_alias, .keyword_include, .keyword_includedir => return,
                else => {},
            }
            _ = self.advance();
        }
    }

    fn errorAtCurrent(self: *Self, message: []const u8) error{ParseError, OutOfMemory} {
        try self.errors.append(self.allocator, .{
            .message = message,
            .line = self.current.line,
            .column = self.current.column,
            .token_lexeme = self.current.lexeme,
        });
        self.had_error = true;
        return error.ParseError;
    }

    fn errorAtPrevious(self: *Self, message: []const u8) error{ParseError, OutOfMemory} {
        try self.errors.append(self.allocator, .{
            .message = message,
            .line = self.previous.line,
            .column = self.previous.column,
            .token_lexeme = self.previous.lexeme,
        });
        self.had_error = true;
        return error.ParseError;
    }

    /// Get all parse errors
    pub fn getErrors(self: *Self) []const ParseError {
        return self.errors.items;
    }

    /// Check if parsing had any errors
    pub fn hadError(self: *Self) bool {
        return self.had_error;
    }
};

fn isAllUppercase(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c >= 'a' and c <= 'z') return false;
        if (c != '_' and (c < 'A' or c > 'Z') and (c < '0' or c > '9')) return false;
    }
    return true;
}

fn looksLikeIpAddress(s: []const u8) bool {
    var dot_count: usize = 0;
    for (s) |c| {
        if (c == '.') dot_count += 1 else if (c != '/' and (c < '0' or c > '9')) return false;
    }
    return dot_count >= 1;
}

pub fn parse(allocator: Allocator, source: []const u8) !ast.Sudoers {
    var parser = Parser.init(allocator, source);
    defer parser.deinit();
    return parser.parse();
}

pub fn parseFile(allocator: Allocator, path: []const u8) !ast.Sudoers {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const source = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(source);
    return parse(allocator, source);
}

/// Error types for include processing
pub const IncludeError = error{
    IncludeDepthExceeded,
    CircularInclude,
    FileNotFound,
    OutOfMemory,
    ParseError,
    AccessDenied,
    Unexpected,
};

/// Parse a sudoers file with @include/@includedir support
/// This recursively loads included files and merges them into the main sudoers structure
pub fn parseWithIncludes(allocator: Allocator, path: []const u8) !ast.Sudoers {
    // Parse the main file first
    var sudoers = try parseFile(allocator, path);
    errdefer sudoers.deinit();
    
    // Track visited files to prevent circular includes
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();
    try visited.put(path, {});
    
    // Process includes (non-recursively using a work queue approach)
    var pending_includes = std.ArrayListUnmanaged(IncludeDirective){};
    defer pending_includes.deinit(allocator);
    
    // Copy initial includes to pending list
    for (sudoers.includes.items) |inc| {
        try pending_includes.append(allocator, inc);
    }
    
    var depth: usize = 0;
    const MAX_INCLUDE_DEPTH = 128;
    
    while (pending_includes.items.len > 0 and depth < MAX_INCLUDE_DEPTH) {
        const include = pending_includes.orderedRemove(0);
        depth += 1;
        
        if (include.is_directory) {
            // @includedir: load all files in directory
            processIncludeDir(allocator, include.path, &sudoers, &visited, &pending_includes) catch continue;
        } else {
            // @include: load single file
            processIncludeFile(allocator, include.path, &sudoers, &visited, &pending_includes) catch continue;
        }
    }
    
    return sudoers;
}

const IncludeDirective = ast.IncludeDirective;

fn processIncludeFile(
    allocator: Allocator,
    path: []const u8,
    sudoers: *ast.Sudoers,
    visited: *std.StringHashMap(void),
    pending: *std.ArrayListUnmanaged(IncludeDirective),
) !void {
    // Skip if already visited
    if (visited.contains(path)) return;
    try visited.put(path, {});
    
    // Parse the included file
    var included = parseFile(allocator, path) catch return;
    defer included.deinit();
    
    // Add new includes to pending
    for (included.includes.items) |inc| {
        try pending.append(allocator, inc);
    }
    
    // Merge into main sudoers
    try mergeSudoers(allocator, sudoers, &included);
}

fn processIncludeDir(
    allocator: Allocator,
    dir_path: []const u8,
    sudoers: *ast.Sudoers,
    visited: *std.StringHashMap(void),
    pending: *std.ArrayListUnmanaged(IncludeDirective),
) !void {
    // Open directory
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();
    
    // Collect valid filenames
    var files = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (files.items) |f| allocator.free(f);
        files.deinit(allocator);
    }
    
    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        // Skip directories
        if (entry.kind == .directory) continue;
        
        // Skip files starting with . or ending with ~
        if (entry.name.len == 0) continue;
        if (entry.name[0] == '.') continue;
        if (entry.name[entry.name.len - 1] == '~') continue;
        
        // Skip files containing . (e.g., file.rpmsave, file.dpkg-old)
        if (std.mem.indexOf(u8, entry.name, ".") != null) continue;
        
        // Add to list
        const name_copy = try allocator.dupe(u8, entry.name);
        try files.append(allocator, name_copy);
    }
    
    // Sort filenames (sudo processes in sorted order)
    std.mem.sort([]const u8, files.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    
    // Process each file
    for (files.items) |filename| {
        const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, filename });
        defer allocator.free(full_path);
        
        processIncludeFile(allocator, full_path, sudoers, visited, pending) catch continue;
    }
}

fn mergeSudoers(allocator: Allocator, dest: *ast.Sudoers, src: *ast.Sudoers) !void {
    // Merge defaults
    for (src.defaults.items) |default| {
        try dest.defaults.append(allocator, default);
    }
    
    // Merge aliases
    var user_iter = src.aliases.user.iterator();
    while (user_iter.next()) |entry| {
        try dest.aliases.user.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    
    var host_iter = src.aliases.host.iterator();
    while (host_iter.next()) |entry| {
        try dest.aliases.host.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    
    var cmnd_iter = src.aliases.cmnd.iterator();
    while (cmnd_iter.next()) |entry| {
        try dest.aliases.cmnd.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    
    var runas_iter = src.aliases.runas.iterator();
    while (runas_iter.next()) |entry| {
        try dest.aliases.runas.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    
    // Merge user specs
    for (src.user_specs.items) |spec| {
        try dest.user_specs.append(allocator, spec);
    }
    
    // Clear src lists without freeing items (they're now owned by dest)
    src.defaults.items.len = 0;
    src.user_specs.items.len = 0;
}

test "parse simple user spec" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "root ALL=(ALL:ALL) ALL");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
}

test "parse defaults" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Defaults env_reset");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try std.testing.expectEqualStrings("env_reset", sudoers.defaults.items[0].name);
}

test "parse user alias" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "User_Alias ADMINS = alice, bob, charlie");
    defer sudoers.deinit();
    try std.testing.expect(sudoers.aliases.user.contains("ADMINS"));
}

test "parse NOPASSWD tag" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "alice ALL=(ALL) NOPASSWD: ALL");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try std.testing.expectEqual(false, cmnd_spec.tags.passwd.?);
}

test "parse group user" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "%wheel ALL=(ALL) ALL");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
}

test "isAllUppercase" {
    try std.testing.expect(isAllUppercase("ADMINS"));
    try std.testing.expect(isAllUppercase("ALL"));
    try std.testing.expect(!isAllUppercase("admins"));
    try std.testing.expect(!isAllUppercase("alice"));
}

test "parse include directive" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "@include /etc/sudoers.d/local");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.includes.items.len);
    try std.testing.expectEqualStrings("/etc/sudoers.d/local", sudoers.includes.items[0].path);
    try std.testing.expectEqual(false, sudoers.includes.items[0].is_directory);
}

test "parse includedir directive" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "@includedir /etc/sudoers.d");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.includes.items.len);
    try std.testing.expectEqualStrings("/etc/sudoers.d", sudoers.includes.items[0].path);
    try std.testing.expectEqual(true, sudoers.includes.items[0].is_directory);
}

test "parse multiple defaults on same line" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Defaults env_reset, secure_path=\"/usr/bin\"");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 2), sudoers.defaults.items.len);
    try std.testing.expectEqualStrings("env_reset", sudoers.defaults.items[0].name);
    try std.testing.expectEqualStrings("secure_path", sudoers.defaults.items[1].name);
}

test "parse defaults with negation" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Defaults !requiretty");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try std.testing.expectEqualStrings("requiretty", sudoers.defaults.items[0].name);
    try std.testing.expectEqual(ast.DefaultOperator.negate, sudoers.defaults.items[0].operator);
}

test "parse defaults with add operator" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Defaults env_keep+=\"HOME\"");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try std.testing.expectEqualStrings("env_keep", sudoers.defaults.items[0].name);
    try std.testing.expectEqual(ast.DefaultOperator.add, sudoers.defaults.items[0].operator);
}

test "parse defaults with remove operator" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Defaults env_keep-=\"LD_PRELOAD\"");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try std.testing.expectEqualStrings("env_keep", sudoers.defaults.items[0].name);
    try std.testing.expectEqual(ast.DefaultOperator.remove, sudoers.defaults.items[0].operator);
}

test "parse host alias" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Host_Alias SERVERS = server1, server2, server3");
    defer sudoers.deinit();
    try std.testing.expect(sudoers.aliases.host.contains("SERVERS"));
    const host_list = sudoers.aliases.host.get("SERVERS").?;
    try std.testing.expectEqual(@as(usize, 3), host_list.len());
}

test "parse cmnd alias" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Cmnd_Alias SHUTDOWN = /sbin/halt, /sbin/reboot, /sbin/poweroff");
    defer sudoers.deinit();
    try std.testing.expect(sudoers.aliases.cmnd.contains("SHUTDOWN"));
    const cmnd_list = sudoers.aliases.cmnd.get("SHUTDOWN").?;
    try std.testing.expectEqual(@as(usize, 3), cmnd_list.len());
}

test "parse runas alias" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Runas_Alias DB = oracle, mysql, postgres");
    defer sudoers.deinit();
    try std.testing.expect(sudoers.aliases.runas.contains("DB"));
}

test "parse negated user" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "!baduser ALL=(ALL) ALL");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    try std.testing.expectEqual(true, user_item.negated);
}

test "parse user with uid" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "#1000 ALL=(ALL) ALL");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    try std.testing.expectEqual(ast.UserValue{ .uid = 1000 }, user_item.value);
}

test "parse multiple tags" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "alice ALL=(ALL) NOPASSWD: NOEXEC: /usr/bin/vim");
    defer sudoers.deinit();
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try std.testing.expectEqual(false, cmnd_spec.tags.passwd.?);
    try std.testing.expectEqual(true, cmnd_spec.tags.noexec.?);
}

test "parse runas with group" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "alice ALL=(root:wheel) ALL");
    defer sudoers.deinit();
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try std.testing.expect(cmnd_spec.runas != null);
    try std.testing.expect(cmnd_spec.runas.?.users != null);
    try std.testing.expect(cmnd_spec.runas.?.groups != null);
}

test "parse command with args" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "alice ALL=(ALL) /usr/bin/apt update");
    defer sudoers.deinit();
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    const cmnd_item = cmnd_spec.commands.items.items[0];
    switch (cmnd_item.value) {
        .command => |cmd| {
            try std.testing.expectEqualStrings("/usr/bin/apt", cmd.path);
            try std.testing.expectEqualStrings("update", cmd.args.?);
        },
        else => try std.testing.expect(false),
    }
}

test "parse complete sudoers file" {
    const allocator = std.testing.allocator;
    const source =
        \\# Sample sudoers file
        \\Defaults env_reset
        \\Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        \\
        \\# User alias
        \\User_Alias ADMINS = alice, bob
        \\
        \\# Host alias  
        \\Host_Alias SERVERS = web1, web2, db1
        \\
        \\# Command alias
        \\Cmnd_Alias SERVICES = /usr/bin/systemctl
        \\
        \\# Rules
        \\root ALL=(ALL:ALL) ALL
        \\%wheel ALL=(ALL) ALL
        \\ADMINS SERVERS=(ALL) NOPASSWD: SERVICES
        \\
        \\@includedir /etc/sudoers.d
    ;
    var sudoers = try parse(allocator, source);
    defer sudoers.deinit();

    // Check defaults
    try std.testing.expectEqual(@as(usize, 2), sudoers.defaults.items.len);

    // Check aliases
    try std.testing.expect(sudoers.aliases.user.contains("ADMINS"));
    try std.testing.expect(sudoers.aliases.host.contains("SERVERS"));
    try std.testing.expect(sudoers.aliases.cmnd.contains("SERVICES"));

    // Check user specs
    try std.testing.expectEqual(@as(usize, 3), sudoers.user_specs.items.len);

    // Check includes
    try std.testing.expectEqual(@as(usize, 1), sudoers.includes.items.len);
    try std.testing.expectEqual(true, sudoers.includes.items[0].is_directory);
}

test "parse scoped defaults for user" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "Defaults:alice !requiretty");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    switch (sudoers.defaults.items[0].scope) {
        .user_list => |user_list| {
            try std.testing.expectEqual(@as(usize, 1), user_list.len());
        },
        else => try std.testing.expect(false),
    }
}

test "error reporting with line and column" {
    const allocator = std.testing.allocator;
    var parser_instance = Parser.init(allocator, "alice ALL = @@invalid");
    defer parser_instance.deinit();

    _ = parser_instance.parse() catch |err| {
        if (err == error.ParseError) {
            // Check that we got error information
            const errors = parser_instance.getErrors();
            try std.testing.expect(errors.len > 0);
            try std.testing.expect(errors[0].line >= 1);
            return;
        }
        return err;
    };
    // If parse succeeds, that's unexpected
    try std.testing.expect(false);
}

test "parse error format" {
    const err = ParseError{
        .message = "unexpected token",
        .line = 10,
        .column = 5,
        .token_lexeme = "@@",
    };
    var buf: [256]u8 = undefined;
    const result = err.toString(&buf);
    try std.testing.expect(std.mem.indexOf(u8, result, "10:5") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "unexpected token") != null);
}

test "parse empty input" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 0), sudoers.user_specs.items.len);
    try std.testing.expectEqual(@as(usize, 0), sudoers.defaults.items.len);
}

test "parse comments only" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator,
        \\# This is a comment
        \\# Another comment
        \\
    );
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 0), sudoers.user_specs.items.len);
}

test "parse netgroup user" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "+netgroup ALL=(ALL) ALL");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    switch (user_item.value) {
        .netgroup => |ng| try std.testing.expectEqualStrings("netgroup", ng),
        else => try std.testing.expect(false),
    }
}

test "parse non-unix group" {
    const allocator = std.testing.allocator;
    var sudoers = try parse(allocator, "%:domain_admins ALL=(ALL) ALL");
    defer sudoers.deinit();
    try std.testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    switch (user_item.value) {
        .non_unix_group => |g| try std.testing.expectEqualStrings("domain_admins", g),
        else => try std.testing.expect(false),
    }
}
