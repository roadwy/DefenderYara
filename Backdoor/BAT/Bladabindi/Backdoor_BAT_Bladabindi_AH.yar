
rule Backdoor_BAT_Bladabindi_AH{
	meta:
		description = "Backdoor:BAT/Bladabindi.AH,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6e 6a 52 41 54 2e 70 72 6f 63 2e 72 65 73 6f 75 72 63 65 73 } //0a 00 
		$a_01_1 = {42 75 69 6c 64 65 72 2e 72 65 73 6f 75 72 63 65 73 } //0a 00 
		$a_01_2 = {6e 6a 52 41 54 2e 43 68 61 74 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
		$a_01_3 = {00 67 16 00 00 3b b8 b7 0b 7f 32 3e 76 73 33 4c ac 00 dc 06 } //00 01 
	condition:
		any of ($a_*)
 
}