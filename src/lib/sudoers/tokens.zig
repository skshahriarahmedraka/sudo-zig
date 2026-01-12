//! Sudoers file tokenizer
//!
//! This module handles tokenizing sudoers files into a stream of tokens
//! that can be consumed by the parser.

const std = @import("std");

/// Token types for sudoers grammar
pub const TokenType = enum {
    // Keywords
    keyword_defaults,
    keyword_host_alias,
    keyword_user_alias,
    keyword_cmnd_alias,
    keyword_runas_alias,
    keyword_include,
    keyword_includedir,

    // Operators
    equals,
    plus_equals,
    minus_equals,
    bang,
    colon,
    comma,
    open_paren,
    close_paren,

    // Values
    identifier,
    quoted_string,
    command_path,
    command_args,

    // Special identifiers
    all, // ALL keyword
    groupname, // %group
    uid, // #uid
    gid, // %#gid
    netgroup, // +netgroup
    non_unix_group, // %:group
    non_unix_gid, // %:#gid

    // Tags
    tag_passwd,
    tag_nopasswd,
    tag_setenv,
    tag_nosetenv,
    tag_noexec,
    tag_exec,
    tag_log_input,
    tag_nolog_input,
    tag_log_output,
    tag_nolog_output,

    // Digest algorithms
    sha224,
    sha256,
    sha384,
    sha512,

    // Wildcards
    wildcard, // * or ?
    glob_pattern, // pattern with wildcards

    // Whitespace and comments
    newline,
    comment,
    line_continuation,

    // End of file
    eof,

    // Error token
    invalid,
};

/// A token from the sudoers file
pub const Token = struct {
    type: TokenType,
    lexeme: []const u8,
    line: u32,
    column: u32,

    pub fn format(
        self: Token,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("Token({s}, \"{s}\", {}:{})", .{
            @tagName(self.type),
            self.lexeme,
            self.line,
            self.column,
        });
    }
};

/// Tokenizer for sudoers files
pub const Tokenizer = struct {
    source: []const u8,
    position: usize,
    line: u32,
    column: u32,
    at_line_start: bool,

    const Self = @This();

    /// Initialize a new tokenizer with the given source
    pub fn init(source: []const u8) Self {
        return .{
            .source = source,
            .position = 0,
            .line = 1,
            .column = 1,
            .at_line_start = true,
        };
    }

    /// Get the next token from the source
    pub fn next(self: *Self) Token {
        self.skipWhitespaceAndContinuation();

        if (self.isAtEnd()) {
            return self.makeToken(.eof, "");
        }

        const start_line = self.line;
        const start_column = self.column;
        const start_pos = self.position;

        const c = self.advance();

        // Handle comments vs UIDs
        // A '#' followed by digits is a UID, otherwise it's a comment (if at line start)
        if (c == '#') {
            if (isDigit(self.peek())) {
                // This is a UID like #1000
                return self.scanUidOrComment(start_pos, start_line, start_column);
            } else if (self.at_line_start) {
                return self.scanComment(start_pos, start_line, start_column);
            }
        }

        // Handle newlines
        if (c == '\n') {
            self.at_line_start = true;
            return .{
                .type = .newline,
                .lexeme = self.source[start_pos..self.position],
                .line = start_line,
                .column = start_column,
            };
        }

        self.at_line_start = false;

        // Handle operators and punctuation
        switch (c) {
            '=' => {
                return .{
                    .type = .equals,
                    .lexeme = self.source[start_pos..self.position],
                    .line = start_line,
                    .column = start_column,
                };
            },
            '+' => {
                if (self.peek() == '=') {
                    _ = self.advance();
                    return .{
                        .type = .plus_equals,
                        .lexeme = self.source[start_pos..self.position],
                        .line = start_line,
                        .column = start_column,
                    };
                }
                // Could be a netgroup
                return self.scanNetgroup(start_pos, start_line, start_column);
            },
            '-' => {
                if (self.peek() == '=') {
                    _ = self.advance();
                    return .{
                        .type = .minus_equals,
                        .lexeme = self.source[start_pos..self.position],
                        .line = start_line,
                        .column = start_column,
                    };
                }
                return self.makeTokenAt(.invalid, start_pos, start_line, start_column);
            },
            '!' => {
                return .{
                    .type = .bang,
                    .lexeme = self.source[start_pos..self.position],
                    .line = start_line,
                    .column = start_column,
                };
            },
            ':' => {
                return .{
                    .type = .colon,
                    .lexeme = self.source[start_pos..self.position],
                    .line = start_line,
                    .column = start_column,
                };
            },
            ',' => {
                return .{
                    .type = .comma,
                    .lexeme = self.source[start_pos..self.position],
                    .line = start_line,
                    .column = start_column,
                };
            },
            '(' => {
                return .{
                    .type = .open_paren,
                    .lexeme = self.source[start_pos..self.position],
                    .line = start_line,
                    .column = start_column,
                };
            },
            ')' => {
                return .{
                    .type = .close_paren,
                    .lexeme = self.source[start_pos..self.position],
                    .line = start_line,
                    .column = start_column,
                };
            },
            '"' => {
                return self.scanQuotedString(start_pos, start_line, start_column);
            },
            '%' => {
                return self.scanGroupOrGid(start_pos, start_line, start_column);
            },
            '#' => {
                return self.scanUidOrComment(start_pos, start_line, start_column);
            },
            '/' => {
                return self.scanCommandPath(start_pos, start_line, start_column);
            },
            '@' => {
                return self.scanInclude(start_pos, start_line, start_column);
            },
            else => {
                if (isIdentifierStart(c)) {
                    return self.scanIdentifierOrKeyword(start_pos, start_line, start_column);
                }
                return self.makeTokenAt(.invalid, start_pos, start_line, start_column);
            },
        }
    }

    /// Peek at the next token without consuming it
    pub fn peek_token(self: *Self) Token {
        const saved_pos = self.position;
        const saved_line = self.line;
        const saved_col = self.column;
        const saved_at_line_start = self.at_line_start;

        const token = self.next();

        self.position = saved_pos;
        self.line = saved_line;
        self.column = saved_col;
        self.at_line_start = saved_at_line_start;

        return token;
    }

    // ============================================
    // Private helper methods
    // ============================================

    fn isAtEnd(self: *Self) bool {
        return self.position >= self.source.len;
    }

    fn peek(self: *Self) u8 {
        if (self.isAtEnd()) return 0;
        return self.source[self.position];
    }

    fn peekNext(self: *Self) u8 {
        if (self.position + 1 >= self.source.len) return 0;
        return self.source[self.position + 1];
    }

    fn advance(self: *Self) u8 {
        const c = self.source[self.position];
        self.position += 1;
        if (c == '\n') {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        return c;
    }

    fn skipWhitespaceAndContinuation(self: *Self) void {
        while (!self.isAtEnd()) {
            const c = self.peek();
            switch (c) {
                ' ', '\t', '\r' => {
                    _ = self.advance();
                },
                '\\' => {
                    // Line continuation
                    if (self.peekNext() == '\n') {
                        _ = self.advance(); // consume backslash
                        _ = self.advance(); // consume newline
                    } else {
                        return;
                    }
                },
                else => return,
            }
        }
    }

    fn makeToken(self: *Self, token_type: TokenType, lexeme: []const u8) Token {
        return .{
            .type = token_type,
            .lexeme = lexeme,
            .line = self.line,
            .column = self.column,
        };
    }

    fn makeTokenAt(self: *Self, token_type: TokenType, start_pos: usize, start_line: u32, start_column: u32) Token {
        return .{
            .type = token_type,
            .lexeme = self.source[start_pos..self.position],
            .line = start_line,
            .column = start_column,
        };
    }

    fn scanComment(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        while (!self.isAtEnd() and self.peek() != '\n') {
            _ = self.advance();
        }
        return .{
            .type = .comment,
            .lexeme = self.source[start_pos..self.position],
            .line = start_line,
            .column = start_column,
        };
    }

    fn scanQuotedString(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        while (!self.isAtEnd() and self.peek() != '"' and self.peek() != '\n') {
            if (self.peek() == '\\' and self.peekNext() == '"') {
                _ = self.advance(); // skip backslash
            }
            _ = self.advance();
        }

        if (self.isAtEnd() or self.peek() == '\n') {
            return .{
                .type = .invalid,
                .lexeme = self.source[start_pos..self.position],
                .line = start_line,
                .column = start_column,
            };
        }

        _ = self.advance(); // closing quote
        return .{
            .type = .quoted_string,
            .lexeme = self.source[start_pos..self.position],
            .line = start_line,
            .column = start_column,
        };
    }

    fn scanGroupOrGid(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        // %group, %#gid, %:nonunixgroup, %:#nonunixgid
        if (self.peek() == ':') {
            _ = self.advance(); // consume ':'
            if (self.peek() == '#') {
                _ = self.advance(); // consume '#'
                // Non-unix GID
                while (!self.isAtEnd() and isDigit(self.peek())) {
                    _ = self.advance();
                }
                return .{
                    .type = .non_unix_gid,
                    .lexeme = self.source[start_pos..self.position],
                    .line = start_line,
                    .column = start_column,
                };
            }
            // Non-unix group name
            while (!self.isAtEnd() and isIdentifierChar(self.peek())) {
                _ = self.advance();
            }
            return .{
                .type = .non_unix_group,
                .lexeme = self.source[start_pos..self.position],
                .line = start_line,
                .column = start_column,
            };
        } else if (self.peek() == '#') {
            _ = self.advance(); // consume '#'
            // Unix GID
            while (!self.isAtEnd() and isDigit(self.peek())) {
                _ = self.advance();
            }
            return .{
                .type = .gid,
                .lexeme = self.source[start_pos..self.position],
                .line = start_line,
                .column = start_column,
            };
        } else {
            // Unix group name
            while (!self.isAtEnd() and isIdentifierChar(self.peek())) {
                _ = self.advance();
            }
            return .{
                .type = .groupname,
                .lexeme = self.source[start_pos..self.position],
                .line = start_line,
                .column = start_column,
            };
        }
    }

    fn scanUidOrComment(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        // Already consumed '#', check if this is a UID (digits) or comment
        if (isDigit(self.peek())) {
            while (!self.isAtEnd() and isDigit(self.peek())) {
                _ = self.advance();
            }
            return .{
                .type = .uid,
                .lexeme = self.source[start_pos..self.position],
                .line = start_line,
                .column = start_column,
            };
        }
        // It's a comment
        return self.scanComment(start_pos, start_line, start_column);
    }

    fn scanCommandPath(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        // Already consumed '/', scan the rest of the path
        while (!self.isAtEnd()) {
            const c = self.peek();
            if (c == ' ' or c == '\t' or c == '\n' or c == ',' or c == ':' or c == '\\') {
                break;
            }
            _ = self.advance();
        }
        return .{
            .type = .command_path,
            .lexeme = self.source[start_pos..self.position],
            .line = start_line,
            .column = start_column,
        };
    }

    fn scanNetgroup(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        // Already consumed '+', scan the netgroup name
        while (!self.isAtEnd() and isIdentifierChar(self.peek())) {
            _ = self.advance();
        }
        return .{
            .type = .netgroup,
            .lexeme = self.source[start_pos..self.position],
            .line = start_line,
            .column = start_column,
        };
    }

    fn scanInclude(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        // Handle @include and @includedir
        while (!self.isAtEnd() and isIdentifierChar(self.peek())) {
            _ = self.advance();
        }
        const lexeme = self.source[start_pos..self.position];
        if (std.mem.eql(u8, lexeme, "@include")) {
            return .{
                .type = .keyword_include,
                .lexeme = lexeme,
                .line = start_line,
                .column = start_column,
            };
        } else if (std.mem.eql(u8, lexeme, "@includedir")) {
            return .{
                .type = .keyword_includedir,
                .lexeme = lexeme,
                .line = start_line,
                .column = start_column,
            };
        }
        return .{
            .type = .invalid,
            .lexeme = lexeme,
            .line = start_line,
            .column = start_column,
        };
    }

    fn scanIdentifierOrKeyword(self: *Self, start_pos: usize, start_line: u32, start_column: u32) Token {
        while (!self.isAtEnd()) {
            const c = self.peek();
            if (isIdentifierChar(c)) {
                _ = self.advance();
            } else if (c == '-') {
                // Check if this is -= operator (don't include in identifier)
                if (self.peekNext() == '=') {
                    break;
                }
                // Otherwise include hyphen in identifier (e.g., host-name)
                _ = self.advance();
            } else {
                break;
            }
        }

        const lexeme = self.source[start_pos..self.position];

        // Check for keywords
        const token_type = getKeywordType(lexeme);
        return .{
            .type = token_type,
            .lexeme = lexeme,
            .line = start_line,
            .column = start_column,
        };
    }
};

// ============================================
// Helper functions
// ============================================

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

fn isAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

fn isIdentifierStart(c: u8) bool {
    return isAlpha(c) or c == '_';
}

fn isIdentifierChar(c: u8) bool {
    return isAlpha(c) or isDigit(c) or c == '_';
}

fn isIdentifierCharExtended(c: u8) bool {
    // Allow hyphen in identifiers but not at boundaries where it could be -= operator
    return isAlpha(c) or isDigit(c) or c == '_' or c == '-';
}

fn getKeywordType(lexeme: []const u8) TokenType {
    const keywords = .{
        .{ "ALL", TokenType.all },
        .{ "Defaults", TokenType.keyword_defaults },
        .{ "Host_Alias", TokenType.keyword_host_alias },
        .{ "User_Alias", TokenType.keyword_user_alias },
        .{ "Cmnd_Alias", TokenType.keyword_cmnd_alias },
        .{ "Runas_Alias", TokenType.keyword_runas_alias },
        .{ "PASSWD", TokenType.tag_passwd },
        .{ "NOPASSWD", TokenType.tag_nopasswd },
        .{ "SETENV", TokenType.tag_setenv },
        .{ "NOSETENV", TokenType.tag_nosetenv },
        .{ "NOEXEC", TokenType.tag_noexec },
        .{ "EXEC", TokenType.tag_exec },
        .{ "LOG_INPUT", TokenType.tag_log_input },
        .{ "NOLOG_INPUT", TokenType.tag_nolog_input },
        .{ "LOG_OUTPUT", TokenType.tag_log_output },
        .{ "NOLOG_OUTPUT", TokenType.tag_nolog_output },
        .{ "sha224", TokenType.sha224 },
        .{ "sha256", TokenType.sha256 },
        .{ "sha384", TokenType.sha384 },
        .{ "sha512", TokenType.sha512 },
    };

    inline for (keywords) |kw| {
        if (std.mem.eql(u8, lexeme, kw[0])) {
            return kw[1];
        }
    }

    return .identifier;
}

// ============================================
// Tests
// ============================================

test "tokenize simple user spec" {
    const source = "root ALL=(ALL:ALL) ALL";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t1.type);
    try std.testing.expectEqualStrings("root", t1.lexeme);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.all, t2.type);

    const t3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.equals, t3.type);

    const t4 = tokenizer.next();
    try std.testing.expectEqual(TokenType.open_paren, t4.type);

    const t5 = tokenizer.next();
    try std.testing.expectEqual(TokenType.all, t5.type);

    const t6 = tokenizer.next();
    try std.testing.expectEqual(TokenType.colon, t6.type);

    const t7 = tokenizer.next();
    try std.testing.expectEqual(TokenType.all, t7.type);

    const t8 = tokenizer.next();
    try std.testing.expectEqual(TokenType.close_paren, t8.type);

    const t9 = tokenizer.next();
    try std.testing.expectEqual(TokenType.all, t9.type);

    const t10 = tokenizer.next();
    try std.testing.expectEqual(TokenType.eof, t10.type);
}

test "tokenize defaults" {
    const source = "Defaults env_reset";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.keyword_defaults, t1.type);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t2.type);
    try std.testing.expectEqualStrings("env_reset", t2.lexeme);
}

test "tokenize group and uid" {
    var tokenizer = Tokenizer.init("%wheel #0 %#100");

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.groupname, t1.type);
    try std.testing.expectEqualStrings("%wheel", t1.lexeme);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.uid, t2.type);
    try std.testing.expectEqualStrings("#0", t2.lexeme);

    const t3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.gid, t3.type);
    try std.testing.expectEqualStrings("%#100", t3.lexeme);
}

test "tokenize command path" {
    const source = "/usr/bin/apt";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.command_path, t1.type);
    try std.testing.expectEqualStrings("/usr/bin/apt", t1.lexeme);
}

test "tokenize NOPASSWD tag" {
    const source = "NOPASSWD:";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.tag_nopasswd, t1.type);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.colon, t2.type);
}

test "tokenize comment" {
    const source = "# This is a comment\nroot";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.comment, t1.type);
    try std.testing.expectEqualStrings("# This is a comment", t1.lexeme);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.newline, t2.type);

    const t3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t3.type);
    try std.testing.expectEqualStrings("root", t3.lexeme);
}

test "tokenize line continuation" {
    const source = "root \\\nALL";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t1.type);
    try std.testing.expectEqualStrings("root", t1.lexeme);

    // Line continuation is skipped, next token is ALL
    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.all, t2.type);
}

test "tokenize quoted string" {
    const source = "\"hello world\"";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.quoted_string, t1.type);
    try std.testing.expectEqualStrings("\"hello world\"", t1.lexeme);
}

test "tokenize alias definition" {
    const source = "User_Alias ADMINS = alice, bob";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.keyword_user_alias, t1.type);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t2.type);
    try std.testing.expectEqualStrings("ADMINS", t2.lexeme);

    const t3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.equals, t3.type);

    const t4 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t4.type);
    try std.testing.expectEqualStrings("alice", t4.lexeme);

    const t5 = tokenizer.next();
    try std.testing.expectEqual(TokenType.comma, t5.type);

    const t6 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t6.type);
    try std.testing.expectEqualStrings("bob", t6.lexeme);
}

test "tokenize include directive" {
    const source = "@include /etc/sudoers.d/custom";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.keyword_include, t1.type);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.command_path, t2.type);
    try std.testing.expectEqualStrings("/etc/sudoers.d/custom", t2.lexeme);
}

test "tokenize includedir directive" {
    const source = "@includedir /etc/sudoers.d";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.keyword_includedir, t1.type);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.command_path, t2.type);
}

test "tokenize sha256 digest" {
    const source = "sha256:abc123";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.sha256, t1.type);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.colon, t2.type);

    const t3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t3.type);
    try std.testing.expectEqualStrings("abc123", t3.lexeme);
}

test "tokenize uid at line start" {
    const source = "#1000 ALL=(ALL) ALL";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.uid, t1.type);
    try std.testing.expectEqualStrings("#1000", t1.lexeme);
}

test "tokenize non-unix group" {
    const source = "%:domain_admins";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.non_unix_group, t1.type);
    try std.testing.expectEqualStrings("%:domain_admins", t1.lexeme);
}

test "tokenize non-unix gid" {
    const source = "%:#12345";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.non_unix_gid, t1.type);
    try std.testing.expectEqualStrings("%:#12345", t1.lexeme);
}

test "tokenize minus equals operator" {
    const source = "env_keep-=\"TEST\"";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t1.type);
    try std.testing.expectEqualStrings("env_keep", t1.lexeme);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.minus_equals, t2.type);

    const t3 = tokenizer.next();
    try std.testing.expectEqual(TokenType.quoted_string, t3.type);
}

test "tokenize plus equals operator" {
    const source = "env_keep+=\"HOME\"";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t1.type);
    try std.testing.expectEqualStrings("env_keep", t1.lexeme);

    const t2 = tokenizer.next();
    try std.testing.expectEqual(TokenType.plus_equals, t2.type);
}

test "tokenize all tags" {
    const tags = [_]struct { src: []const u8, expected: TokenType }{
        .{ .src = "PASSWD", .expected = .tag_passwd },
        .{ .src = "NOPASSWD", .expected = .tag_nopasswd },
        .{ .src = "SETENV", .expected = .tag_setenv },
        .{ .src = "NOSETENV", .expected = .tag_nosetenv },
        .{ .src = "EXEC", .expected = .tag_exec },
        .{ .src = "NOEXEC", .expected = .tag_noexec },
        .{ .src = "LOG_INPUT", .expected = .tag_log_input },
        .{ .src = "NOLOG_INPUT", .expected = .tag_nolog_input },
        .{ .src = "LOG_OUTPUT", .expected = .tag_log_output },
        .{ .src = "NOLOG_OUTPUT", .expected = .tag_nolog_output },
    };

    for (tags) |tag| {
        var tokenizer = Tokenizer.init(tag.src);
        const t = tokenizer.next();
        try std.testing.expectEqual(tag.expected, t.type);
    }
}

test "tokenize hostname with hyphen" {
    const source = "web-server-01";
    var tokenizer = Tokenizer.init(source);

    const t1 = tokenizer.next();
    try std.testing.expectEqual(TokenType.identifier, t1.type);
    try std.testing.expectEqualStrings("web-server-01", t1.lexeme);
}
