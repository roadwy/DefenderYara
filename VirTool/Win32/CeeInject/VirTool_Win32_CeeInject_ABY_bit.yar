
rule VirTool_Win32_CeeInject_ABY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 75 ?? 5b 8a 82 } //1
		$a_03_1 = {30 04 37 4e 79 f5 90 09 05 00 e8 } //1
		$a_03_2 = {88 0c 07 8a 4d ?? 47 88 0c 07 8a 4d ?? 22 ca 0a 4d ?? 47 88 0c 07 03 75 ?? 8b 45 ?? 47 3b 30 } //1
		$a_03_3 = {7c ea 50 56 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 39 35 ?? ?? ?? ?? 76 1f 8b 0d ?? ?? ?? ?? 8a 8c 08 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}