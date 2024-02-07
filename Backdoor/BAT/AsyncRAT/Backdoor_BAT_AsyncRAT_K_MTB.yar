
rule Backdoor_BAT_AsyncRAT_K_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 01 a2 25 17 28 90 01 01 00 00 0a a2 25 18 28 90 01 01 00 00 0a a2 25 19 28 90 01 01 00 00 0a a2 25 1a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 28 90 01 01 00 00 0a 8c 90 01 01 00 00 01 a2 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0a de 90 00 } //02 00 
		$a_03_1 = {07 20 80 00 00 00 6f 90 01 01 00 00 0a 07 17 6f 90 01 01 00 00 0a 07 18 6f 90 01 01 00 00 0a 07 02 90 00 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 53 75 62 4b 65 79 } //01 00  CreateSubKey
		$a_01_3 = {53 65 74 56 61 6c 75 65 } //00 00  SetValue
	condition:
		any of ($a_*)
 
}