
rule Backdoor_BAT_Crysan_AA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0b 03 17 fe 02 16 fe 01 0c 08 2c 04 07 0a 2b 34 03 0d 17 13 04 2b 24 07 28 90 01 01 00 00 0a 11 04 fe 04 13 05 11 05 2c 0d 72 90 01 03 70 07 28 90 01 01 00 00 0a 0b 00 00 11 04 17 d6 13 04 11 04 09 31 d7 07 0a 2b 00 06 2a 90 00 } //03 00 
		$a_81_1 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 } //03 00 
		$a_81_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //03 00 
		$a_81_3 = {46 74 70 57 65 62 52 65 71 75 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}