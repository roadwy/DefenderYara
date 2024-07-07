
rule Backdoor_BAT_QuasarRAT_D_MTB{
	meta:
		description = "Backdoor:BAT/QuasarRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 1f 90 01 01 9d 6f 90 01 01 00 00 0a 90 09 06 00 00 00 0a 17 8d 90 00 } //2
		$a_03_1 = {07 11 06 06 11 06 9a 1f 90 01 01 28 90 01 01 00 00 0a 9c 11 06 17 58 90 00 } //2
		$a_03_2 = {00 00 01 25 16 1f 90 01 01 9d 6f 90 01 01 00 00 0a 90 09 06 00 00 00 04 17 8d 90 00 } //2
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}