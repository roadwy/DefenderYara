
rule VirTool_Win32_CeeInject_CY{
	meta:
		description = "VirTool:Win32/CeeInject.CY,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 76 6f 48 6a 69 76 75 79 7c 70 7f 80 50 84 76 77 77 85 00 } //1
		$a_01_1 = {75 5a 73 7c 3c 3b 58 7b 79 6e 71 80 81 00 } //1
		$a_01_2 = {4f 76 4a 69 79 49 76 76 7d 6f 83 80 61 76 81 75 72 76 00 } //1
		$a_03_3 = {60 31 c0 40 0f a2 89 1d ?? ?? 40 00 89 15 ?? ?? 40 00 61 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*10) >=12
 
}