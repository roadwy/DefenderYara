
rule VirTool_Win32_Injector_EP{
	meta:
		description = "VirTool:Win32/Injector.EP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {42 8d 85 dd 82 ff ff 8a ?? 88 } //1
		$a_03_1 = {2d 88 00 00 00 36 8b 45 f4 8b 43 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 0f 84 ?? ?? 00 00 36 8b 45 f4 } //1
		$a_03_2 = {8b 43 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 74 ?? eb } //1
		$a_03_3 = {8b 43 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 0f 84 ?? 00 00 00 e9 } //1
		$a_03_4 = {8b 42 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 0f 84 ?? ?? 00 00 e9 } //1
		$a_01_5 = {8d 85 dd 82 ff ff 33 c9 8a 08 33 4e 04 88 08 40 4a 75 f3 8d 85 dd 82 ff ff ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}