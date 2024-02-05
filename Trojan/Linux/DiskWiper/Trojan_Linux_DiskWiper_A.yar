
rule Trojan_Linux_DiskWiper_A{
	meta:
		description = "Trojan:Linux/DiskWiper.A,SIGNATURE_TYPE_CMDHSTR_EXT,3c 00 3c 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {64 00 64 00 20 00 } //37 00 
		$a_00_1 = {6f 00 66 00 3d 00 2f 00 64 00 65 00 76 00 2f 00 73 00 64 00 61 00 } //fb ff 
		$a_00_2 = {6d 00 6b 00 69 00 6e 00 69 00 74 00 72 00 61 00 6d 00 66 00 73 00 } //fb ff 
		$a_00_3 = {75 00 2d 00 62 00 6f 00 6f 00 74 00 2e 00 69 00 6d 00 78 00 } //fb ff 
		$a_00_4 = {2e 00 69 00 73 00 6f 00 } //fb ff 
		$a_00_5 = {2e 00 69 00 6d 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}