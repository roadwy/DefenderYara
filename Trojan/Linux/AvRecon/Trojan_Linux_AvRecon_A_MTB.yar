
rule Trojan_Linux_AvRecon_A_MTB{
	meta:
		description = "Trojan:Linux/AvRecon.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6d 6f 64 65 6c 2e 74 78 74 } //01 00 
		$a_01_1 = {58 2d 50 72 6f 74 6f 2d 53 74 6f 72 61 67 65 } //01 00 
		$a_01_2 = {58 2d 50 72 6f 74 6f 2d 4a 69 64 } //01 00 
		$a_01_3 = {56 49 4c 4b 41 } //01 00 
		$a_01_4 = {3f 70 65 74 3d 6d 61 72 61 6c 26 61 67 65 3d } //01 00 
		$a_01_5 = {64 6e 73 73 6d 61 73 71 } //01 00 
		$a_01_6 = {37 35 37 41 36 44 37 45 33 33 36 44 36 44 } //00 00 
	condition:
		any of ($a_*)
 
}