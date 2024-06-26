
rule Trojan_Linux_LinuxAttackTools_A{
	meta:
		description = "Trojan:Linux/LinuxAttackTools.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 6c 00 6f 00 77 00 6c 00 6f 00 72 00 69 00 73 00 } //0a 00  slowloris
		$a_00_1 = {70 00 72 00 6f 00 78 00 79 00 63 00 68 00 61 00 69 00 6e 00 73 00 } //0a 00  proxychains
		$a_00_2 = {20 00 61 00 72 00 6d 00 69 00 74 00 61 00 67 00 65 00 } //0a 00   armitage
		$a_00_3 = {6c 00 69 00 6e 00 75 00 78 00 2d 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 2d 00 73 00 75 00 67 00 67 00 65 00 73 00 74 00 65 00 72 00 } //0a 00  linux-exploit-suggester
		$a_00_4 = {6a 00 64 00 77 00 70 00 2d 00 73 00 68 00 65 00 6c 00 6c 00 69 00 66 00 69 00 65 00 72 00 2e 00 70 00 79 00 } //0a 00  jdwp-shellifier.py
		$a_00_5 = {6c 00 69 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 68 00 69 00 64 00 65 00 72 00 } //0a 00  libprocesshider
		$a_00_6 = {6d 00 69 00 6d 00 69 00 70 00 65 00 6e 00 67 00 75 00 69 00 6e 00 } //00 00  mimipenguin
	condition:
		any of ($a_*)
 
}