
rule VirTool_Win32_Injector_HJ{
	meta:
		description = "VirTool:Win32/Injector.HJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {ff d2 85 c0 0f 84 86 0d 00 00 6a 04 68 00 10 00 00 6a 04 6a 00 a1 ?? ?? ?? ?? ff d0 89 45 fc 33 c9 75 3f } //1
		$a_01_1 = {ff d0 85 c0 0f 84 b0 0b 00 00 6a 00 6a 04 8d 4d ec 51 8b 55 fc 8b 82 a4 00 00 00 83 c0 08 50 8b 4d dc 51 8b 15 d4 14 42 00 ff d2 } //1
		$a_01_2 = {6a 00 8b 4d f4 8b 51 54 52 8b 45 0c 50 8b 4d d8 51 8b 55 dc 52 a1 ec 14 42 00 ff d0 33 c9 75 } //1
		$a_01_3 = {8b 55 fc 52 8b 45 e0 50 8b 0d d0 14 42 00 ff d1 33 d2 75 } //1
		$a_01_4 = {8b 45 e0 50 8b 0d f4 14 42 00 ff d1 33 d2 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}