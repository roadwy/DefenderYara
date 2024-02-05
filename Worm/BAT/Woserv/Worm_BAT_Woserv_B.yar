
rule Worm_BAT_Woserv_B{
	meta:
		description = "Worm:BAT/Woserv.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {38 02 00 00 00 26 16 28 90 01 01 01 00 06 02 73 90 01 01 00 00 0a 7d 01 00 00 04 02 28 90 01 01 00 00 0a 2a 90 00 } //01 00 
		$a_00_1 = {57 6f 72 6d 53 65 72 76 69 63 65 } //01 00 
		$a_00_2 = {70 61 73 73 77 6f 72 64 } //01 00 
		$a_00_3 = {68 69 64 64 65 6e } //01 00 
		$a_00_4 = {41 74 74 61 63 6b 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}