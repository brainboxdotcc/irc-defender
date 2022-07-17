# $Id: hybrid.pm 1612 2005-07-07 12:42:40Z brain $

my %hosts = ();

sub link_init
{
        if (!main::depends("core-v1")) {
                print "This module requires version 1.x of defender.\n";
                exit(0);
        }
        main::provides("server","hybrid-server");
}

sub rawirc
{
	my $out = $_[0];
	my $first = "$out\n\r";
	syswrite(SH, $first, length($first));
	print ">> $out\n" if $debug;
}


sub privmsg
{
	my $nick = $_[0];
	my $msg = $_[1];
	my $first = "PRIVMSG $nick :$msg\n\r";
	syswrite(SH, $first, length($first));
}


sub notice
{
	my $nick = $_[0];
	my $msg = $_[1];
	my $first = "NOTICE $nick :$msg\n\r";
	syswrite(SH, $first, length($first));
}

sub message
{
	my $line = shift;
	$line = ":$botnick PRIVMSG $mychan :$line";
	&rawirc($line);
}

sub mode
{
        my ($dest,$line) = @_;
        $line = ":$botnick MODE $dest $line";
        &rawirc($line);
}

sub globops
{
	# because hybrid doesnt seem to be coded with the mindset that things should
	# be sent to all servers like this, defender implements a non-native version
	# of globops which works by maintaining a list of opers (users with +ola
	# userflags) and sending them individual snotices.
	my $msg = shift;
	foreach my $mask (%hosts) {
        	if (defined($hosts{$mask}{isoper})) {
			if ($hosts{$mask}{isoper} eq "yes") {
				&rawirc(":$servername NOTICE $mask :*** Global: $msg");
			}
		}
	}
}

sub message_to
{
        my ($dest,$line) = @_;
        $line = ":$botnick PRIVMSG $dest :$line";
        &rawirc($line);
}


sub killuser
{
        my($nick,$reason) = @_;
        &rawirc(":$botnick KILL $nick :$botnick ($reason)");
	$KILLED++;
}

sub gline
{
	# Hybrid 7 doesn't support GLINEs, this is done effectively by
	# setting a remote KLINE on all servers (*). This requires a
	# U:Line (shared {} block) for the defender server.
	my($hostname,$duration,$reason) = @_;
	my ($ident,$host) = split("@",$hostname);
	my $delta = time + $duration;
	&rawirc(":$botnick KLINE * $delta $ident $host :AKILL active: $reason");
	$KILLED++;
}

sub gethost
{
	my($nick) = @_;
	$nick = lc($nick);
	return $hosts{$nick}{host};
}

sub getmatching
{
	my @results = ();
	my($re) = @_;
	foreach my $mask (%hosts) {
		if (defined($hosts{$mask}{host})) {
			if ($hosts{$mask}{host} =~ /$re/i) {
				push @results, $mask;
			}
		}
	}
	return @results;
}

sub connect {
	$CONNECT_TYPE = "Server";

	print ("Creating socket...\n");
        socket(SH, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || print "socket() failed: $!\n";
        if (defined($main::dataValues{"bind"})) {
		print "Bound to ip address: " . $main::dataValues{"bind"} . "\n";
                bind(SH, sockaddr_in(0, inet_aton($main::dataValues{"bind"})));
        }
        else {
		bind(SH, sockaddr_in(0, INADDR_ANY));
        }

	print ("Connecting to $server\:$port...\n");
        my $sin = sockaddr_in ($port,inet_aton($server));
        connect(SH,$sin) || print "Could not connect to server: $!\n";

	print ("Logging in...\n");
	&rawirc("PASS $password :TS");
	&rawirc("CAPAB :KLN GLN HOPS");
	&rawirc("SERVER $servername 1 :$serverdesc");

	print ("Introducing pseudoclient: $botnick...\n");
	# NICK [Brain] 1 1079188995 +aiow brain cpc2-mapp3-6-0-cust198.nott.cable.ntl.com hybrid.test.chatspike.net :There are no secrets except those that
	my $now = time;
	&rawirc("NICK $botnick 1 $now +aiow $botnick $domain $servername :$botname");

	print ("Joining channel...\n");
	&rawirc(":$servername SJOIN $now $mychan +tn :\@$botnick");
}

sub pingreply {
	$string = $_[0];
	@per = split(':', $string, 2);
	$pier = $per[1];
	$ret = "PONG :$pier";
	&rawirc($ret);
}


sub reconnect {
	close SH;
	&connect;
	&poll;
}

my $njtime = time+20;

sub checkmodes
{
	# this sub checks a nick's modes to see if theyre an oper or not
	# if they have +o theyre judged as being oper, and are inserted
	# into an @opers list which is used by non-native globops.
	my ($nick,$modes) = @_;
	if ($modes =~ /^\+/) { # adding modes
		if ($modes =~ /^\+.*(o|a|l).*$/) {
			$hosts{lc($nick)}{isoper} = "yes";
		}
	}
	if ($modes =~ /^-/) { # taking modes
		if ($modes =~ /^-.*(o|a|l).*$/) {
			$hosts{lc($nick)}{isoper} = "no";
		}
	}
}

sub isoper
{
        my($nick) = @_;
        if ($hosts{lc($nick)}{isoper} eq "yes") {
                return 1;
        } else {
                return 0;
        }
}

sub poll {

	$KILLED = 0;
	$CONNECTS = 0;

	while (chomp($buffer = <SH>))
	{
		chop($buffer);

		print "<< $buffer\n" if $debug;

		if (($NETJOIN != 0) && (time > $njtime))
	        {
                	$NETJOIN = 0;
	                print "$njservername completed NETJOIN state (merge time exceeded)\n";
        	}

		
                if ($buffer =~ /KICK/i)
                {
                        &rawirc(":$botnick JOIN $mychan");
                }

		if ($buffer =~ /^ERROR :(.+?)$/)
		{
			print "ERROR received from ircd: $1\n";
			print "You might need to check your C/N lines or link block on the ircd, or port number you are using.\n";
			exit(0);
		}

		if ($buffer =~ /^:(.+) REHASH (.+)$/)
		{
			my $rnick = $1;
			if ($2 =~ /$servername/)
			{
				&globops("$servername rehashing at request of \002$rnick\002");
				&rehash;
				foreach my $line (@rehash_data) {
				        notice($rnick,$line);
				}
			}
		}
		# :Brain4 NICK [Brain] 1078842182
		if ($buffer =~ /^:(.+?)\sNICK\s(.+?)\s[0-9]+$/)
		{
			$oldnick = quotemeta($1);
			$newnick = quotemeta($2);

			$hosts{lc($2)}{host} = $hosts{lc($1)}{host};
			$hosts{lc($2)}{isoper} = $hosts{lc($1)}{isoper};

			foreach $mod (@modlist) {
				eval ("Modules::Scan::" . $mod ."::handle_nick(\"$oldnick\",\"$newnick\")");
			}
		}

		if ($buffer =~ /^NICK\s(.+?)\s\d+\s\d+\s(.+?)\s(.+?)\s(.+?)\s(.+?)\s:(.+?)$/)
		{
			$thenick = $1;
			$themodes = $2;
			$theident = $3;
			$thehost = $4;
			$theserver = $5;
			$thegecos = $6;
			$CONNECTS++;
			# :Defender PRIVMSG [Brain] 1 1078621980 :VERSION
			if ($thenick =~ / /)
			{
				($thenick) = split(" ",$thenick);
			}

			$hosts{lc($thenick)}{host} = "$theident\@$thehost";
			$hosts{lc($thenick)}{isoper} = "no";

			&checkmodes($thenick,$themodes);

			$thegecos = quotemeta($thegecos);
			$thenick = quotemeta($thenick);
			foreach $mod (@modlist) {
			        my $func = ("Modules::Scan::" . $mod . "::scan_user(\"$theident\",\"$thehost\",\"$theserver\",\"$thenick\",\"$thegecos\",0)");
			        eval $func;
				print $@ if $@;
			}
		}
                # :[Brain] TOPIC #chatspike [Brain] 1099522169 :moo moo
                if ($buffer =~ /^\:(.+?)\sTOPIC\s(.+?)\s\S+\s\d+\s:(.+?)$/)
                {
                        $thenick = $1;
                        $thetarget = $2;
                        $params = $3;
                        $params =~ s/^\://;
                        $thenick = quotemeta($thenick);
                        $thetarget = quotemeta($thetarget);
                        $params = quotemeta($params);
                        foreach $mod (@modlist) {
                                my $func = ("Modules::Scan::" . $mod . "::handle_topic(\"$thenick\",\"$thetarget\",\"$params\")");
                                eval $func;
                        }
                }
		if ($buffer =~ /^\:(.+?)\sMODE\s(.+?)\s(.+?)$/)
		{
			$thenick = $1;
			$thetarget = $2;
			$params = $3;
			$params =~ s/^\://;
			&checkmodes($thetarget,$params);
			$thenick = quotemeta($thenick);
			$thetarget = quotemeta($thetarget);
			$params = quotemeta($params);
			foreach $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::handle_mode(\"$thenick\",\"$thetarget\",\"$params\")");
				eval $func;
			}
		}
		# :[Brain] KILL Defender :NetAdmin.chatspike.net![Brain] (kill test)
		if ($buffer =~ /^\:(.+?)\sKILL\s(.+?)\s:(.+?)$/)
		{
			my $killedby = $1;
			my $killnick = $2;
			my $killreason = $3;
			if ($killnick =~ /^\Q$botnick\E$/i)
			{
				&rawirc("NICK $botnick 1 1077205492 $botnick $domain $servername 0 +oiSq $domain :$botname");
				&rawirc(":$botnick JOIN $mychan");
				&rawirc(":$servername KILL $killedby :$servername (Do \002NOT\002 kill $botnick!)");
			}
		}

		if ($buffer =~ /^:(.+?)\sQUIT\s:(.+?)$/)
		{
			my $quitnick = $1;
			my $quitreason = $2;
			delete $hosts{$quitnick}{host};
			delete $hosts{$quitnick}{isoper};
		}

		if ($buffer =~ /^:(.+?)\sSJOIN\s\d+\s(.+?)\s(.+?)\s:(.+?)$/)
		{
			# a hybrid SJOIN can contain multiple nicks, if a channel merges
			# during a netsplit.
			$theserv = $1;
			$thenick = $4;
			$thetarget = $2;
			$thetarget = quotemeta($thetarget);
			while ($thenick =~ /^(.+?)\s(.+?)$/) {  # we have multiple nicks in the SJOIN
				print "Processing multiple-nick sjoin\n" if $debug;
				$thenick =~ /^(.+?)\s.+?$/;
				$tn2 = $1;
				$thenick =~ /^.+?\s(.+?)$/;
				$thenick = $1;
				$tn2 =~ s/^(\%|\@|\+)//;
				$tn2 = quotemeta($tn2);
				foreach $mod (@modlist) {
					my $func = ("Modules::Scan::" . $mod . "::handle_join(\"$tn2\",\"$thetarget\")");
					eval $func;
				}
								
			}
			$thenick =~ s/^(\%|\@|\+)//;
			$thenick = quotemeta($thenick);
			foreach $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::handle_join(\"$thenick\",\"$thetarget\")");
				eval $func;
			}
		}
		
		if ($buffer =~ /^:(.+?)\sPART\s(.+?)$/)
		{
			$thenick = $1;
			$thetarget = $2;
			if ($thetarget =~ / /) {
				$thetarget = split(" ",$thetarget);
			}
			$thenick = quotemeta($thenick);
			$thetarget = quotemeta($thetarget);
			foreach $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::handle_part(\"$thenick\",\"$thetarget\")");
				eval $func;
			}
		}

		if ($buffer =~ /^:(.+?)\sSERVER\s(.+?)\s(.+?)\s:(.+?)/)
		{
			$NETJOIN = 1;
			$njservername = $2;
			print "$njservername joined the net and began synching\n";
			$njtime = time+80;
		}
		if ($buffer =~ /^SERVER\s(.+?)\s(.+?)\s:(.+?)/)
		{
			$NETJOIN = 1;
			$njservername = $1;
			print "uplink ($servername) is synching...\n";
			$njtime = time+80;
		}

		if ($buffer =~ /^:(.+?)\sNOTICE\s(.+?)\s:(.+?)$/)
		{
			&noticehandler($buffer);
		}

		elsif ($buffer =~ /^:(.+?)\sPRIVMSG\s(.+?)\s:(.+?)$/) {
			&msghandler($buffer);
		}

		elsif ($buffer =~ /^:(.+) WHOIS (.+) :.+$/) {
			$source = $1;
			# :bender.chatspike.net 320 [Brain] [Brain] :has whacked 33 virus drones
			&rawirc(":$servername 311 $source $botnick $botnick $domain * :$botname");
                        &rawirc(":$servername 312 $source $botnick $servername :$serverdesc");
			&rawirc(":$servername 313 $source $botnick :Is a network service");
                        &rawirc(":$servername 318 $source $botnick :End of /WHOIS list.");

		}
		else
		{
		        if (substr($buffer,0,4) =~ /ping/i)
			{
			        &pingreply($buffer);
       			}
		}
	}
	&reconnect;
}


# sig handler

sub shutdown {
	#print "SIGINT caught\n";
	&rawirc(":$botnick QUIT :Defender terminating");
	print("Disconnecting from irc server (SIGINT)\n");
	&rawirc(":$servername SQUIT :$quitmsg");
	close SH;
	exit;
}

sub handle_alarm
{
}

1;
