use strict;
use warnings;
use utf8;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib";
use lib "$FindBin::Bin/../plugins/MTMCP/lib";

use MT::Session;
use MT::Author;
use MTMCP::Auth;
use MTMCP::OAuth;

# MT 本体は mt_session.duration を「失効時刻（epoch）」として扱い、
# MT::Session::purge が duration <= time の行を削除する。これは
# run-periodic-tasks から定期的に呼ばれるため、duration に経過秒数を
# 入れると発行直後のレコードが消える。
#
# このテストは、プラグインが発行する全 kind のレコードについて
#   (1) duration が失効時刻として保存されていること
#   (2) 定期タスク相当の purge で消えないこと
#   (3) 検証側が duration を失効時刻として比較していること
# を確かめる。

sub _seed_author {
    my ($id) = @_;
    my $u = MT::Author->new;
    $u->id($id);
    $u->name("user$id");
    $u->save;
    return $u;
}

sub _reset {
    MT::Session::reset();
    MT::Author::reset();
}

# duration が「今から TTL 秒後」の失効時刻になっているか。
# time() をまたぐ実行を許容して 5 秒の誤差を認める。
sub _is_expiry_at {
    my ($session, $ttl, $label) = @_;
    my $expected = time() + $ttl;
    my $actual   = $session->duration;
    ok(abs($actual - $expected) <= 5, $label)
        or diag("duration=$actual expected≈$expected (ttl=$ttl)");
}

# --- アクセストークン（DA）---
{
    _reset();
    my $author = _seed_author(1);
    my $token  = MTMCP::Auth::issue_token_for($author);

    my $s = MT::Session->load($token);
    ok($s, 'アクセストークンのセッションが保存される');
    is($s->kind, 'DA', 'kind は DA');
    _is_expiry_at($s, 604800, 'DA の duration は 7 日後の失効時刻');

    cmp_ok($s->duration, '>', time(), 'DA の duration は未来');
    is_deeply([MT::Session->expired_ids], [], '定期タスクの削除対象にならない');

    MT::Session->purge;
    ok(MT::Session->load($token), 'purge 後もアクセストークンが残る');
}

# --- リフレッシュトークン（DT）---
{
    _reset();
    my $author = _seed_author(1);
    my $token  = MTMCP::Auth::issue_refresh_token_for($author);

    my $s = MT::Session->load($token);
    is($s->kind, 'DT', 'kind は DT');
    _is_expiry_at($s, 30 * 24 * 60 * 60, 'DT の duration は 30 日後の失効時刻');

    MT::Session->purge;
    ok(MT::Session->load($token), 'purge 後もリフレッシュトークンが残る');
}

# --- リフレッシュトークンの消費（DU マーカー）---
{
    _reset();
    my $author = _seed_author(1);
    my $token  = MTMCP::Auth::issue_refresh_token_for($author);

    my $resolved = MTMCP::Auth::resolve_refresh_session($token);
    ok($resolved, '有効なリフレッシュトークンは解決できる');
    is($resolved->get('author_id'), 1, 'author_id が取れる');

    my ($claim) = grep { $_->kind eq 'DU' } values %MT::Session::STORE;
    ok($claim, '消費済みマーカーが作られる');
    _is_expiry_at($claim, 30 * 24 * 60 * 60, 'DU の duration は失効時刻');

    MT::Session->purge;
    ok(
        (grep { $_->kind eq 'DU' } values %MT::Session::STORE),
        'purge 後も消費済みマーカーが残る（消えると再利用を許してしまう）'
    );
}

# --- 期限切れのリフレッシュトークンは拒否する（検証側）---
{
    _reset();
    my $author = _seed_author(1);
    my $token  = MTMCP::Auth::issue_refresh_token_for($author);

    # 失効時刻を過去に倒す
    MT::Session->load($token)->duration(time() - 1);
    is(MTMCP::Auth::resolve_refresh_session($token), undef,
        '失効時刻を過ぎたリフレッシュトークンは undef');
}

# --- ログイン失敗の記録（DF）---
{
    _reset();
    MTMCP::Auth::_record_failure('someone@example.com');

    my ($rec) = grep { $_->kind eq 'DF' } values %MT::Session::STORE;
    ok($rec, 'ログイン失敗が記録される');
    _is_expiry_at($rec, 900, 'DF の duration は 15 分後の失効時刻');

    MT::Session->purge;
    ok(
        (grep { $_->kind eq 'DF' } values %MT::Session::STORE),
        'purge 後も失敗記録が残る（消えるとロックアウトが働かない）'
    );

    # 時間窓の中で数えつづける
    MTMCP::Auth::_record_failure('someone@example.com');
    my ($again) = grep { $_->kind eq 'DF' } values %MT::Session::STORE;
    is($again->get('count'), 2, '同じ時間窓では失敗回数を積み上げる');
}

# --- 認可コード（DC）---
{
    _reset();
    my $author = _seed_author(1);
    my $code   = MTMCP::OAuth::issue_code(
        author         => $author,
        redirect_uri   => 'https://example.com/cb',
        code_challenge => 'challenge',
        client_id      => 'client-1',
    );

    my $s = MT::Session->load({ id => $code, kind => 'DC' });
    ok($s, '認可コードが保存される');
    _is_expiry_at($s, 600, 'DC の duration は 10 分後の失効時刻');

    MT::Session->purge;
    ok(MT::Session->load({ id => $code, kind => 'DC' }),
        'purge 後も認可コードが残る');
}

# --- クライアント登録（DR）---
{
    _reset();
    MTMCP::OAuth::_store_client('client-1', ['https://example.com/cb'], 'Test Client');

    my $s = MT::Session->load({ id => 'client-1', kind => 'DR' });
    ok($s, 'クライアント登録が保存される');
    _is_expiry_at($s, 10 * 365 * 24 * 3600, 'DR の duration は 10 年後の失効時刻');

    MT::Session->purge;
    ok(MT::Session->load({ id => 'client-1', kind => 'DR' }),
        'purge 後もクライアント登録が残る');

    is_deeply(
        MTMCP::OAuth::_lookup_client_redirect_uris('client-1'),
        ['https://example.com/cb'],
        '登録した redirect_uri を引ける',
    );
}

# --- 回帰防止: duration に経過秒数を入れると定期タスクで消える ---
{
    _reset();
    my $s = MT::Session->new;
    $s->id('relative-seconds');
    $s->kind('DA');
    $s->start(time());
    $s->duration(604800);    # 誤り: 経過秒数
    $s->save;

    is_deeply([MT::Session->expired_ids], ['relative-seconds'],
        '経過秒数を入れたレコードは失効済みと判定される');

    MT::Session->purge;
    is(MT::Session->load('relative-seconds'), undef,
        '経過秒数を入れたレコードは purge で消える（これが #67 の不具合）');
}

done_testing();
