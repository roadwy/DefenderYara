
rule Trojan_Linux_WrapFtp_A_xp{
	meta:
		description = "Trojan:Linux/WrapFtp.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 6e 65 74 72 63 62 61 6b } //01 00  /tmp/netrcbak
		$a_01_1 = {2f 68 6f 6d 65 2f 68 6f 67 65 2f 2e 6e 65 74 72 63 } //01 00  /home/hoge/.netrc
		$a_01_2 = {63 68 6d 6f 64 20 67 6f 2d 72 77 78 20 25 73 } //01 00  chmod go-rwx %s
		$a_01_3 = {46 54 50 20 73 65 72 76 65 72 20 72 65 61 64 79 } //00 00  FTP server ready
	condition:
		any of ($a_*)
 
}