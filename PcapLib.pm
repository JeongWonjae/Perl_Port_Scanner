# /etc/perl

use strict;
use warnings;

use utf8;
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use PortStatus;

sub Pcap_Start{
	my $dst_port; my $dst_host; my $mode, my $tmp, my $src_host, my $flag_option;
	($dst_port, $dst_host, $mode, $src_host, $flag_option)=@_;
	my $syn, my $fin, my $rst, my $psh, my $urg, my $ack;

	#find network device
	my $err=q{};
	my $dev=pcap_lookupdev(\$err);
	print "******\n";
	print "[INFO] Connect to ", $dev, "\n";

	my $pcap=pcap_open_live($dev,1024,1,0,\$err);

	#declaration filter string
	my $filter;
	my $filter_str="src host $dst_host and dst host $src_host and src port $dst_port";

	#filter compile, and apply
	pcap_compile($pcap, \$filter, $filter_str, 2, 0);
	pcap_setfilter($pcap, $filter);

	#capture
	print "******\n";
	$tmp=pcap_loop($pcap, 1, \&Process_Packet, "e1");

	#result flags in captured packet
	my $strgFlags="StorageFlags.pl";
	open(FH, "<$strgFlags");
	my $aLine=<FH>;
	($syn, $fin, $rst, $psh, $urg, $ack)=split(":", $aLine);

	#check open or close
	Check_Port($syn, $fin, $rst, $psh, $urg, $ack, $mode, $dst_port, $flag_option);
	print "\n";
	pcap_close($pcap);

	exit;
}


sub Process_Packet{
	my $syn, my $fin, my $rst, my $psh, my $urg, my $ack, my $isflags, my @flagArr, my @tmp;
	my($user_data, $header, $packet)=@_;
	my $ip_obj=NetPacket::IP->decode(eth_strip($packet));
	my $tcp_obj=NetPacket::TCP->decode($ip_obj->{data});

	printf(
		"[RESPONSE] %s:%d->%s:%d (%d)",
		$ip_obj->{src_ip}, $tcp_obj->{src_port},
		$ip_obj->{dest_ip}, $tcp_obj->{dest_port},
		length($tcp_obj->{data})
	);

	print "SYN " if($tcp_obj->{flags} & SYN);
	print "FIN " if($tcp_obj->{flags} & FIN);
	print "RST " if($tcp_obj->{flags} & RST);
	print "PSH " if($tcp_obj->{flags} & PSH);
	print "URG " if($tcp_obj->{flags} & URG);
	print "ACK " if($tcp_obj->{flags} & ACK);
	print "\n******\n";

	$syn=($tcp_obj->{flags} & SYN);
	$fin=($tcp_obj->{flags} & FIN);
	$rst=($tcp_obj->{flags} & RST);
	$psh=($tcp_obj->{flags} & PSH);
	$urg=($tcp_obj->{flags} & URG);
	$ack=($tcp_obj->{flags} & ACK);

	if(length($tcp_obj->{data})>0){
		print $tcp_obj->{data}, "\n";
		print "******\n";
	}

	my $strgFlags="StorageFlags.pl";
	-e $strgFlags || die "[ERROR] $strgFlags.pl is not exist.";
	-T $strgFlags || die "[ERROR] $strgFlags.pl is incorrect file.";

	$#flagArr=5;
	open(FH, ">$strgFlags") || die "[ERROR] Can't open $strgFlags.pl.";
	@tmp=($syn, $fin, $rst, $psh, $urg, $ack);

	foreach(0..5){
		$flagArr[$_]=$tmp[$_];
	}
	$isflags=join(":",@flagArr);
	print FH $isflags;
	close(FH);
}

1;

__END__
