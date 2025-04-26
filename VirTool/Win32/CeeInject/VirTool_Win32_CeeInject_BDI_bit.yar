
rule VirTool_Win32_CeeInject_BDI_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDI!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 c1 e0 04 03 45 e4 8b 4d d4 03 4d ec 33 c1 8b 55 d4 c1 ea 05 03 55 e8 33 c2 8b 4d f4 2b c8 89 4d f4 8b 55 f4 c1 e2 04 03 55 f8 8b 45 f4 03 45 ec 33 d0 8b 4d f4 c1 e9 05 03 4d d8 33 d1 8b 45 d4 2b c2 89 45 d4 } //1
		$a_03_1 = {ff 56 c6 85 ?? ?? ?? ff 74 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 72 c6 85 ?? ?? ?? ff 63 c6 85 ?? ?? ?? ff 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}