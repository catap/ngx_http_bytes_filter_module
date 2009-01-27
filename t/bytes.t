#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for bytes filter module.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(24);

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        location / {
            bytes on;
        }
    }
}

EOF

$t->write_file('t1',
	join('', map { sprintf "X%03dXXXXXX", $_ } (0 .. 99)));
$t->run();

###############################################################################

my $t1;

# normal requests

$t1 = http_get('/t1');
like($t1, qr/200/, 'full reply');
like($t1, qr/Content-Length: 1000/, 'full reply length');
like($t1, qr/^(X[0-9]{3}XXXXXX){100}$/m, 'full reply content');

$t1 = http_get('/t1?bytes=0-');
like($t1, qr/200/, 'full reply filtered');
like($t1, qr/Content-Length: 1000/, 'full reply filtered length');
like($t1, qr/^(X[0-9]{3}XXXXXX){100}$/m, 'full reply filtered content');

$t1 = http_get('/t1?bytes=0-9,100-109,990-');
like($t1, qr/200/, 'complex reply');
like($t1, qr/Content-Length: 30/, 'complex reply length');
like($t1, qr/^(X[0-9]{3}XXXXXX){3}$/m, 'complex reply content');

$t1 = http_get('/t1?bytes=-10');
like($t1, qr/200/, 'final bytes');
like($t1, qr/Content-Length: 10/, 'final bytes length');
like($t1, qr/^X099XXXXXX$/m, 'final bytes content');

# various range requests

$t1 = http_get_range('/t1?bytes=100-', 'Range: bytes=0-9');
like($t1, qr/206/, 'first bytes - 206 partial reply');
like($t1, qr/Content-Length: 10/, 'first bytes - correct length');
like($t1, qr/Content-Range: bytes 0-9\/900/, 'first bytes - content range');
like($t1, qr/^X010X{6}$/m, 'first bytes - correct content');

$t1 = http_get_range('/t1?bytes=100-', 'Range: bytes=-10');
like($t1, qr/206/, 'final bytes - 206 partial reply');
like($t1, qr/Content-Length: 10/, 'final bytes - content length');
like($t1, qr/Content-Range: bytes 890-899\/900/,
	'final bytes - content range');
like($t1, qr/^X099XXXXXX$/m, 'final bytes - correct content');

$t1 = http_get_range('/t1?bytes=0-12,100-', 'Range: bytes=0-99');
like($t1, qr/206/, 'multi buffers - 206 partial reply');
like($t1, qr/Content-Length: 100/, 'multi buffers - content length');
like($t1, qr/Content-Range: bytes 0-99\/913/, 'multi buffers - content range');
like($t1, qr/^X000X{6}X00X010XXXXXX(X01[1-7]XXXXXX){7}X018XXX$/m,
	'multi buffers - correct content');

###############################################################################

sub http_get_range {
	my ($url, $extra) = @_;
	return http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close
$extra

EOF
}

###############################################################################
