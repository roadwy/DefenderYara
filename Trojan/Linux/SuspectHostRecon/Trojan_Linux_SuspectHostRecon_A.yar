
rule Trojan_Linux_SuspectHostRecon_A{
	meta:
		description = "Trojan:Linux/SuspectHostRecon.A,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {2e 00 31 00 6d 00 61 00 2e 00 78 00 79 00 7a 00 } //10 .1ma.xyz
		$a_00_1 = {40 00 2f 00 65 00 74 00 63 00 2f 00 70 00 61 00 73 00 73 00 77 00 64 00 } //9 @/etc/passwd
		$a_00_2 = {2d 00 2d 00 64 00 61 00 74 00 61 00 } //1 --data
		$a_00_3 = {2d 00 2d 00 70 00 6f 00 73 00 74 00 2d 00 64 00 61 00 74 00 61 00 } //1 --post-data
		$a_00_4 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_00_5 = {70 00 69 00 6e 00 67 00 } //1 ping
		$a_00_6 = {77 00 67 00 65 00 74 00 } //1 wget
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*9+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=21
 
}