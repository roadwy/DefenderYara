
rule PWS_Win32_Spynoon_STR_MTB{
	meta:
		description = "PWS:Win32/Spynoon.STR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {54 5f 5f 32 33 66 33 30 34 30 55 } //01 00 
		$a_81_1 = {54 5f 5f 32 33 66 33 31 35 30 55 } //01 00 
		$a_81_2 = {52 48 65 6c 70 49 6e 74 66 73 } //01 00 
		$a_81_3 = {35 4d 61 73 6b 55 74 69 6c 73 } //01 00 
		$a_81_4 = {52 54 5f 5f 32 33 66 32 65 32 30 55 } //00 00 
	condition:
		any of ($a_*)
 
}