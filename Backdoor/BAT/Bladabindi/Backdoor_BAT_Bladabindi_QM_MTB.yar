
rule Backdoor_BAT_Bladabindi_QM_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1c 13 09 } //10
		$a_80_1 = {74 65 6d 70 5c 41 73 73 65 6d 62 6c 79 2e 65 78 65 } //temp\Assembly.exe  3
		$a_80_2 = {4f 62 66 75 73 63 61 74 69 6f 6e 41 74 74 72 69 62 75 74 65 } //ObfuscationAttribute  3
		$a_80_3 = {53 74 72 69 70 41 66 74 65 72 4f 62 66 75 73 63 61 74 69 6f 6e } //StripAfterObfuscation  3
		$a_80_4 = {59 61 6e 6f 41 74 74 72 69 62 75 74 65 } //YanoAttribute  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}