package NoCat::Source::Passwd;

use NoCat::Source;
use Fcntl qw( :flock );
use Digest::MD5 qw( md5_base64 );
use strict;
use vars qw( @ISA @REQUIRED *FILE );

@ISA	    = qw( NoCat::Source );
@REQUIRED   = qw( 
    UserFile GroupUserFile GroupAdminFile UserIDField UserPasswdField
);

my @GroupFiles = qw( GroupUserFile GroupAdminFile );

sub store {
    my ( $self, $fh, $data ) = @_;
    truncate( $fh, 0 );
    seek( $fh, 0, 0 );

    while (my ($key, $val) = each %$data) {
        print $fh "$key:";
        if (ref $val) {
	    print $fh join( ",", @$val );
        } else {
	    print $fh $val;
        }
	print $fh "\n";
    }	
}

sub file {
    my ( $self, $file, $writeable ) = @_;
    my $fh       = do { \local *FILE };      
    my $lock     = $writeable ? LOCK_EX : LOCK_SH;
    my $mode     = $writeable ? "+<" : "<";
    my $timeout  = time + ( $self->{LockTimeout} || 2 );
    my $result;

    open( $fh, $mode . $self->{$file} ) or die "Can't load $file ($self->{$file}): $!\n";
    1 until $result = flock( $fh, $lock | LOCK_NB ) or time > $timeout;

    die "Can't get exclusive lock on $file ($self->{$file}): $!\n" unless $result;
    return $fh;
}

sub fetch {
    my ( $self, $file, $callback ) = @_;
    my $fh = $self->file( $file, $callback );
    my %hash;

    while (defined(my $line = <$fh>)) {
	chomp $line;
	my ( $name, $data ) = split( ":", $line, 2 );		
	$data = [ split(",", $data) ] if $file =~ /^Group/o;
	$hash{$name} = $data;
    } 

    if ( $callback ) {
	$self->$callback( \%hash );
	$self->store( $fh, \%hash ); 
   }

    return \%hash;
}

# create() stores a new NoCat::User object after it's been populated.
#
sub create_user {
    my ( $self, $user )	= @_;
    $self->store_user( $user );
}

sub check_password {
    my ($self, $user) = @_;
    # MD5 the password if it's not already MD5'd, prior to actually using it.
    $user->set_password( md5_base64( $user->passwd ), 1 ) if $user->changed_password;
    return $user->passwd;
}

sub store_user {
    my ( $self, $user )	= @_;
    my $id = $user->id;
    my $pw = $self->check_password($user);

    $self->fetch( UserFile => sub { $_[1]{$id} = $pw } ); 
}

sub authenticate_user {
    my ($self, $user_pw, $user) = @_;
    my $stored_pw = $self->check_password( $user ); 
    return md5_base64( $user_pw ) eq $stored_pw;
}

sub fetch_user_by_id {
    my ( $self, $id )    = @_;
    my $users = $self->fetch( "UserFile" );
    return { $self->{UserIDField} => $id, $self->{UserPasswdField} => $users->{$id} }
	if $users->{$id};
    return;
}

sub fetch_groups_by_user {
    my ( $self, $user ) = @_;
    my $id = $user->id;
    my %data;

    for my $file ( @GroupFiles ) {
	my $groups = $self->fetch( $file );
	while (my ($group, $users) = each %$groups) {
	    $data{$group} ||= ($file eq "GroupAdminFile")
		if grep( $_ eq $id, @$users );
	} 
    }

    return \%data;
}

sub fetch_users_by_group {
    my ( $self, $group ) = @_;
    my $id = $group->id;
    my %data;

    for my $file ( @GroupFiles ) {
	my $groups = $self->fetch( $file );
	next unless $groups->{$id};
	for my $user ( @{$groups->{$id}} ) {
	    $data{$user} ||= ($file eq "GroupAdminFile");
	}
    }

    return \%data;
}

sub add_group_member {
    my ( $self, $group, $user, $admin ) = @_;
    $self->update_group_member( $group, $user, $admin );
}

sub drop_from_files {
    my ( $self, $group, $user, @files ) = @_;
    my $gid  = $group->id;
    my $thunk = sub {
	my $users = $_[1]{$gid};
	@$users = grep( $_ ne $user, @$users );
    };

    $self->fetch( $_ => $thunk ) for (@files);
}

sub drop_group_member {
    my ( $self, $group, $user ) = @_;
    $self->drop_from_files($group, $user, @GroupFiles);
}

sub update_group_member {
    my ( $self, $group, $user, $admin ) = @_;
    my $gid  = $group->id;

    my ($add, $drop) = ( $admin ? reverse @GroupFiles : @GroupFiles );

    $self->drop_from_files( $group, $user, $drop );
    $self->fetch( $add => sub { 
	my $users = ( $_[1]{$gid} ||= [] );
	my %list  = map {$_ => 1} ( @$users, $user );
	@$users   = keys %list;
    });
}

1;
