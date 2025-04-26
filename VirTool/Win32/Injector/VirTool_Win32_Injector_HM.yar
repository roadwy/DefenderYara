
rule VirTool_Win32_Injector_HM{
	meta:
		description = "VirTool:Win32/Injector.HM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8d 4d e0 51 ff 75 d0 35 ?? ?? ?? ?? 50 ff 75 d4 e8 ?? ?? ?? ?? 53 89 45 64 81 ce ?? ?? ?? ?? ff 55 0c 03 f8 39 5d 64 0f 84 } //1
		$a_03_1 = {ff 75 4c ff 75 64 ff 75 58 ff 55 b8 69 ff ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 83 c4 0c 81 fe ?? ?? ?? ?? 0f 84 } //1
		$a_01_2 = {8b 45 58 8b 4d 4c 8d 1c 08 6a f6 c6 03 e9 ff } //1
		$a_01_3 = {8b 45 64 2b 45 58 6a f6 83 e8 05 89 43 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}