package NoCat::Source::DBI;

use NoCat::Source;
use DBI;
use Digest::MD5 qw( md5_base64 );
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = qw( NoCat::Source );
@REQUIRED   = qw( 
    Database DB_User DB_Passwd UserTable UserIDField 
    GroupTable GroupIDField GroupAdminField
);

sub db {
    my $self = shift;

    unless ( $self->{DB} ) {
	$self->{DB} = DBI->connect( 
	    @$self{qw{ Database DB_User DB_Passwd }},
	    { RaiseError => 1 }
	)
    }

    return $self->{DB};
}

sub where {
    my $self	= shift;
    my $delimit	= shift;
    return join(" $delimit ", map( "$_ = ?", @_ ));
}

# create() stores a new NoCat::User object after it's been populated.
#
sub create_user {
    my ( $self, $user )	= @_;

    # Clear the user timestamp.
    $user->set( $self->{UserStampField} => undef )
	if $self->{UserStampField};

    # Make sure the user's password is crypted.
    $self->check_password( $user );

    # Add the data to the database.
    my $data	= $user->data;
    my @fields	= keys %$data;
    my @place	= ("?") x @fields;

    local $" = ", ";
    $self->db->do( "insert into $self->{UserTable} (@fields) values (@place)", 
	{}, values %$data );
}

sub store_user {
    my ( $self, $user )	= @_;

    # Make sure the user's password is crypted.
    $self->check_password($user);    

    # Update the data in the database.
    my $data	= $user->data;
    my $fields	= $self->where( "," => keys %$data );

    local $" = ", ";
    $self->db->do( "update $self->{UserTable} set $fields where $self->{UserIDField} = ?",
	{}, values %$data, $user->id );
}

sub check_password {
    my ($self, $user) = @_;
    # MD5 the password if it's not already MD5'd, prior to actually using it.
    $user->set_password( md5_base64( $user->passwd ), 1 ) if $user->changed_password;
    return $user->passwd;
}

sub authenticate_user {
    my ($self, $user_pw, $user) = @_;
    my $stored_pw = $self->check_password( $user );
    return md5_base64( $user_pw ) eq $stored_pw;
}

sub fetch_user_by_id {
    my ( $self, $id )    = @_;
    my $st = $self->db->prepare( my $sql = qq/ 
	select * from $self->{UserTable} where $self->{UserIDField} = ? /);
    my %row;

    $st->execute( $id );
    $st->bind_columns(\( @row{ @{$st->{NAME}} } ));
    $st->fetch;

    return \%row;
}

sub fetch_members {
    my ( $self, $sql, @args ) = @_;
    my ( %member, $id, $admin ); 
    
    my $st = $self->db->prepare( $sql );
    $st->execute( @args );
    $st->bind_columns(\( $id, $admin ));
    
    $member{$id} = $admin while $st->fetch;
    
    return \%member;
}

sub fetch_groups_by_user {
    my ( $self, $user ) = @_;
    return $self->fetch_members(qq/ 
	select $self->{GroupIDField}, $self->{GroupAdminField}
	    from $self->{GroupTable} where $self->{UserIDField} = ? /,
	    $user->id 
    );
}

sub fetch_users_by_group {
    my ( $self, $group ) = @_;
    return $self->fetch_members(qq/ 
	select $self->{UserIDField}, $self->{GroupAdminField}
	    from $self->{GroupTable} where $self->{GroupIDField} = ? /,
	    $group->id
    );
}

sub add_group_member {
    my ( $self, $group, $user, $admin ) = @_;

    local $" = ",";
    $self->db->do(qq/
	insert $self->{GroupTable} 
	    (@$self{qw{ GroupIDField UserIDField GroupAdminField }})
	    values ( ?, ?, ? ) /, {}, $group->id, $user, $admin 
    );

}

sub drop_group_member {
    my ( $self, $group, $user ) = @_;
    $self->db->do(qq/ 
	delete from $self->{GroupTable} 
	    where $self->{GroupIDField} = ?
	    and $self->{UserIDField} = ? /,
	    {}, $group->id, $user 
    );
}

sub update_group_member {
    my ( $self, $group, $user, $admin ) = @_;
    $self->db->do(qq/
	update $self->{GroupTable} set $self->{GroupAdminField} = ?
	    where $self->{GroupIDField} = ? 
	    and $self->{UserIDField} = ? /, 
	    {}, $admin, $group->id, $user
    );
}

1;
