
rule PWS_Win32_Spynoon_STR_MTB{
	meta:
		description = "PWS:Win32/Spynoon.STR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 5f 5f 32 33 66 33 30 34 30 55 } //1 T__23f3040U
		$a_81_1 = {54 5f 5f 32 33 66 33 31 35 30 55 } //1 T__23f3150U
		$a_81_2 = {52 48 65 6c 70 49 6e 74 66 73 } //1 RHelpIntfs
		$a_81_3 = {35 4d 61 73 6b 55 74 69 6c 73 } //1 5MaskUtils
		$a_81_4 = {52 54 5f 5f 32 33 66 32 65 32 30 55 } //1 RT__23f2e20U
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}