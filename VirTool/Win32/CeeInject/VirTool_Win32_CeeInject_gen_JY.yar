
rule VirTool_Win32_CeeInject_gen_JY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {99 b9 32 00 00 00 f7 f9 83 c2 32 } //1
		$a_01_1 = {8b 51 3c 8b 45 f8 6b c0 28 03 45 08 8d 8c 10 f8 00 00 00 } //1
		$a_01_2 = {8b 48 3c 8b 55 f8 6b d2 28 03 55 08 8d 84 0a f8 00 00 00 } //1
		$a_03_3 = {0f be 11 0f be 85 ?? ?? ff ff 33 d0 8b 4d ?? 03 8d ?? ?? ff ff 88 11 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}