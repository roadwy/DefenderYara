
rule Worm_BAT_Knowlog_B{
	meta:
		description = "Worm:BAT/Knowlog.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 61 72 65 61 7a 61 53 74 61 72 74 00 45 6d 75 6c 65 53 74 61 72 74 00 } //01 00 
		$a_01_1 = {67 65 74 4d 53 4e 37 35 50 61 73 73 77 6f 72 64 73 } //01 00 
		$a_01_2 = {44 65 73 76 65 72 4d 61 6c 77 61 72 65 62 79 74 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}