use strict;
use warnings;

use PcapLib;
use Socket;
use threads;

my $src_host; my $dst_host;
my $src_port; my $dst_port;
my $mode=""; my $flag_option="";

#save received commands : options
for(my $i=0;$i<=$#ARGV;$i++){
  if($ARGV[$i]=~/-src/i){
    my $tmp_i=$i+1;
    $src_host=$ARGV[$tmp_i];
  }
  if($ARGV[$i]=~/-dst/i){
    my $tmp_i=$i+1;
    $dst_host=$ARGV[$tmp_i];
  }
  if($ARGV[$i]=~/-port/i){
    my $tmp_i=$i+1;
    $src_port=$ARGV[$tmp_i];
    $dst_port=$ARGV[$tmp_i];
  }
  if($ARGV[$i]=~/-flag/i){
	my $tmp_i=$i+1;
	$flag_option=$ARGV[$tmp_i];
  }
  if($ARGV[$i]=~/-m/i){
    my $tmp_i=$i+1;
    $mode=$ARGV[$tmp_i];
  }
  if($ARGV[$i]=~/-help/i){
	my $tmp=<<EOTL;
******
<USAGE>
[Require Option]
1.Source host -> -src <src_ip>
2.Destination host -> -dst <dst_ip>
3.Port -> -port <port>

[MODE Option] -m <mode>
1.TCP OPEN SCAN {Ts}
2.TCP HALF-OPEN SCAN
\t(1)SYN SCAN {Tss}
\t(2)FIN SCAN {Tsf}
\t(3)XMASS SCAN {Tsx}
\t(4)NULL SCAN {Tsn}
3.ACK SCAN {A}

[Flag Option] -flag <flag>
1.SYN {S} 2.ACK {A} 3.FIN {F}
4.RST {R} 5.URG {U} 6.PSH {P}
******
EOTL
 	print "$tmp";
 	exit;
  }
}

print "******\n";
print "[INFO] Starting port scanner *(1.0 version)\n";

#required variable check
if(!defined $src_host or !defined $src_port or !defined $dst_host or !defined $dst_port or ($mode eq "" and $flag_option eq "")) {
	print "******\n";
	print "[ERROR] Wrong command. Use -help option.\n";
	exit;
 }
else {
	print "******\n";
	print "[INFO] Port scan for $dst_host :$dst_port\n";
	main();
 }

#start main
sub main {
	my $src_host_struct = (gethostbyname($src_host))[4];
	my $dst_host_struct = (gethostbyname($dst_host))[4];

	socket(RAW, AF_INET, SOCK_RAW, 255) || die $!;
	setsockopt(RAW, 0, 1, 1);

  #make raw packet
	my ($packet) = Make_Headers($src_host_struct, $src_port, $dst_host_struct, $dst_port, $flag_option, $mode);
	my ($destination) = pack('Sna4x8', AF_INET, $dst_port, $dst_host_struct);

  #capture packet and wait
	my $packetCapture=threads->create(\&Pcap_Start, $dst_port, $dst_host, $mode, $src_host, $flag_option) || die("Packet capture failed.\n");
  sleep(1);

  #send and wait
	send(RAW,$packet,0,$destination);
	sleep(2);

  #when not recv response of stealth scan(fin, xass, null scan)
  if ($flag_option eq ""){
    if ($packetCapture!=0 and ($mode eq "Tsf" or $mode eq "Tsx" or $mode eq "Tsn" )){
  		print "[RESULT] $dst_port port is opened\n";
  	}
    if ($packetCapture!=0 and $mode eq "A"){
      print "[RESULT] $dst_port port is filtered\n";
    }
  }

  if ($mode eq ""){
    if ($packetCapture!=0 and ($flag_option eq "F" or $flag_option eq "f")){
      print "[RESULT] $dst_port port is opened\n";
    }
    if ($packetCapture!=0 and $flag_option=~/F/i){
      if ($flag_option=~/P/i){
        if ($flag_option=~/U/i){
          print "[RESULT] $dst_port port is opened\n";
        }
      }
    }
    if ($packetCapture!=0 and ($flag_option eq "A" or $flag_option eq "a")){
      print "[RESULT] $dst_port port is filtered\n";
    }
  }

  #wait
	sleep(1);
	print "******\n";
}

sub Make_Headers {
	my $source_host; my $source_port; my $destination_host; my $destination_port;
	my $flag; my $m;
	($source_host,$source_port,$destination_host,$destination_port, $flag, $m) = @_;

	my $zero_cksum = 0; #16bits

	#create TCP header
	my $tcp_proto          = 6; #for ip header 'protocol' field
	my ($tcp_len)          = 20;
	my $syn                = 13456; #sequence number / 32bits
	my $ack                = 0; #ack number / 32bits
	my $tcp_headerlen      = "5"; #'5' means 20bytes, 5blocks / 'offset' field / 4bits
	my $tcp_reserved       = 0; #4bits
	my $tcp_head_reserved  = $tcp_headerlen.$tcp_reserved; #8bits

	#set flags / 6bits
	my $tcp_urg = 0;
	my $tcp_ack = 0;
	my $tcp_psh = 0;
	my $tcp_rst = 0;
	my $tcp_syn = 0;
	my $tcp_fin = 0;
	#set mode (or set flags(=below code))
	if($flag eq ""){
		if($m eq "Ts"){
			$tcp_syn=1;
		}
		elsif($m eq "Tss"){
			$tcp_syn=1;
		}
		elsif($m eq "Tsf"){
			$tcp_fin=1;
		}
		elsif($m eq "Tsx"){
			$tcp_fin=1;
			$tcp_psh=1;
			$tcp_urg=1;
		}
		elsif($m eq "Tsn"){
		}
		elsif($m eq "A"){
			$tcp_ack=1;
		}
		else{
			print "[ERROR] Wrong command. Select correct mode.\n";
			exit;
		}
	}
	elsif($m eq ""){
		if($flag=~/U/i){
			$tcp_urg=1;
		}
		if($flag=~/A/i){
			$tcp_ack=1;
		}
		if($flag=~/P/i){
			$tcp_psh=1;
		}
		if($flag=~/R/i){
			$tcp_rst=1;
		}
		if($flag=~/S/i){
			$tcp_syn=1;
		}
		if($flag=~/F/i){
			$tcp_fin=1;
		}
	}

	my $null               = 0;
	my $tcp_win            = 124; #'windows size' field / 16bits
	my $tcp_urg_ptr        = 0; #16bits
	my $tcp_all            = $null . $null . #'flag' field / 8bits
                          $tcp_urg . $tcp_ack .
                          $tcp_psh . $tcp_rst .
                          $tcp_syn . $tcp_fin ;

	#for create checksum / 16bits
	my ($tcp_pseudo) = pack('a4a4CCnnnNNH2B8nvn',$source_host,$destination_host,0,$tcp_proto, $tcp_len,$source_port, $destination_port,$syn,$ack, $tcp_head_reserved,$tcp_all,$tcp_win, $null,$tcp_urg_ptr);
	my ($tcp_checksum) = &Checksum($tcp_pseudo);

	#create IP header
	my $ip_ver             = 4;
	my $ip_len             = 5;
	my $ip_ver_len         = $ip_ver . $ip_len;
	my $ip_tos             = 00;
	my ($ip_tot_len)       = $tcp_len + 20;
	my $ip_frag_id         = 19245;
	my $ip_frag_flag       = "010";
	my $ip_frag_oset       = "0000000000000";
	my $ip_fl_fr           = $ip_frag_flag . $ip_frag_oset;
	my $ip_ttl             = 30;

 	#finally creation
 	my ($pkt) = pack('H2H2nnB16C2na4a4nnNNH2B8nvn', $ip_ver_len,$ip_tos,$ip_tot_len,$ip_frag_id, $ip_fl_fr,$ip_ttl, $tcp_proto,$zero_cksum,$source_host, $destination_host,$source_port,$destination_port,$syn,$ack,$tcp_head_reserved, $tcp_all,$tcp_win,$tcp_checksum,$tcp_urg_ptr);

	return $pkt;
}

#calculate checksum
sub Checksum {
	my ($msg) = @_;
	my ($len_msg,$num_short,$short,$chk);
	$len_msg = length($msg);
	$num_short = $len_msg / 2;
	$chk = 0;
	foreach $short (unpack("S$num_short", $msg)) {
		$chk += $short;
	}
	$chk += unpack("C", substr($msg, $len_msg - 1, 1)) if $len_msg % 2;
	$chk = ($chk >> 16) + ($chk & 0xffff);
	return(~(($chk >> 16) + $chk) & 0xffff);
}

__END__
