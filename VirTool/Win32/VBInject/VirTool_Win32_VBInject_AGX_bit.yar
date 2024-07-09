
rule VirTool_Win32_VBInject_AGX_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGX!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 16 dc 2d 00 [0-20] 58 [0-20] 05 40 24 14 00 [0-20] 39 41 04 [0-20] 68 8d a3 3d 00 [0-20] 58 [0-20] 05 c0 5c 15 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AGX_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 58 28 81 3b 4d 00 53 00 75 f3 81 7b 04 56 00 42 00 75 ea 8b 70 10 56 8b 5e 3c 8b 34 24 01 de 8b 5e 78 8b 04 24 01 d8 89 c6 83 c6 28 ad 85 c0 74 fb 03 04 24 81 38 55 8b ec 83 75 f0 81 78 04 ec 0c 56 8d 75 e7 } //1
		$a_03_1 = {ff 34 0e 81 34 24 ?? ?? ?? ?? 83 e9 04 7d f1 ff e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}