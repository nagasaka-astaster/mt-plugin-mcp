package MT::Session;
use strict;
use warnings;

# MTMCP の認証まわり（Auth.pm / OAuth.pm / App.pm）の単体テスト用スタブ。
#
# duration は MT 本体と同じく「失効時刻（epoch）」として扱う。MT::Session::purge
# が duration <= time の行を削除する挙動を purge() で再現しているので、
# 保存時に相対秒数を入れる実装は expired_ids() / purge() で落ちる。

our %STORE;
our @SAVED;
our @REMOVED;
our $SAVE_ERROR;

sub reset {
    %STORE      = ();
    @SAVED      = ();
    @REMOVED    = ();
    $SAVE_ERROR = undef;
}

sub new {
    my $class = shift;
    bless {
        id       => undef,
        kind     => undef,
        start    => 0,
        duration => 0,
        data     => {},
    }, $class;
}

# スカラー渡しは id 一致、ハッシュ渡しは id / kind の完全一致で引く。
sub load {
    my ($class, $terms) = @_;
    return undef unless defined $terms;

    if (ref $terms eq 'HASH') {
        my $id = $terms->{id};
        return undef unless defined $id;
        my $obj = $STORE{$id} or return undef;
        if (defined $terms->{kind}) {
            return undef unless ($obj->{kind} // '') eq $terms->{kind};
        }
        return $obj;
    }

    return $STORE{$terms};
}

# load 済みのオブジェクトの save は UPDATE、new したオブジェクトの save は
# INSERT。既存 id への INSERT は主キー重複で失敗する（Auth.pm の
# _claim_refresh_token が消費の原子性をこの挙動に依存している）。
sub save {
    my $self = shift;
    return 0 if $SAVE_ERROR;
    return 0 unless defined $self->{id};
    return 0 if !$self->{_loaded} && exists $STORE{ $self->{id} };
    $self->{_loaded} = 1;
    $STORE{ $self->{id} } = $self;
    push @SAVED, $self;
    return 1;
}

sub remove {
    my $self = shift;
    return 0 unless defined $self->{id};
    delete $STORE{ $self->{id} };
    push @REMOVED, $self;
    return 1;
}

sub errstr { $SAVE_ERROR // 'unknown error' }

for my $col (qw(id kind start duration)) {
    no strict 'refs';
    *{$col} = sub {
        my $self = shift;
        $self->{$col} = shift if @_;
        return $self->{$col};
    };
}

sub set {
    my ($self, $key, $value) = @_;
    $self->{data}{$key} = $value;
    return $value;
}

sub get {
    my ($self, $key) = @_;
    return $self->{data}{$key};
}

# MT::Session::purge 相当。duration <= time の行を削除する。
sub purge {
    my ($class, $now) = @_;
    $now //= time();
    my @gone = grep { ($STORE{$_}{duration} // 0) <= $now } keys %STORE;
    delete $STORE{$_} for @gone;
    return @gone;
}

# purge が消す対象の id。テストから「定期タスクで消えるか」を直接確かめる用。
sub expired_ids {
    my ($class, $now) = @_;
    $now //= time();
    return sort grep { ($STORE{$_}{duration} // 0) <= $now } keys %STORE;
}

1;
