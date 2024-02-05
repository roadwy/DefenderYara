
rule PWS_BAT_Stimilini_I{
	meta:
		description = "PWS:BAT/Stimilini.I,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 46 69 6c 65 53 74 65 61 6c 65 72 45 78 74 72 65 6d 65 } //01 00 
		$a_01_1 = {47 6f 6f 67 6c 65 43 68 72 6f 6d 65 } //01 00 
		$a_01_2 = {50 61 73 73 77 6f 72 64 44 61 74 61 } //01 00 
		$a_01_3 = {56 61 6c 76 65 44 61 74 61 46 6f 72 6d 61 74 50 61 72 73 65 72 } //00 00 
		$a_01_4 = {00 67 16 00 00 } //62 b1 
	condition:
		any of ($a_*)
 
}