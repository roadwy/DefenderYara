
rule Backdoor_Win32_Lotok_RT_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {33 46 30 44 53 68 65 6c 6c 65 78 } //01 00 
		$a_81_1 = {68 74 74 70 3a 2f 2f 34 37 2e 31 30 33 2e 32 31 39 2e 37 37 2f 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_81_2 = {4d 46 43 34 32 2e 44 4c 4c } //01 00 
		$a_81_3 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //01 00 
		$a_81_4 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //00 00 
	condition:
		any of ($a_*)
 
}