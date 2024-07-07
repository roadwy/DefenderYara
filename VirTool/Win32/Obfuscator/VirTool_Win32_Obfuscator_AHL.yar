
rule VirTool_Win32_Obfuscator_AHL{
	meta:
		description = "VirTool:Win32/Obfuscator.AHL,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {d2 e0 8a cb 80 c1 09 80 e1 1a 80 e9 04 d2 ea 8b 4d ec 0a c2 88 07 8b 45 08 } //10
		$a_03_1 = {8b 45 ec 8a 04 03 3a 45 08 74 44 90 01 29 43 0f b7 45 f4 83 c0 40 3b d8 0f 82 90 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}