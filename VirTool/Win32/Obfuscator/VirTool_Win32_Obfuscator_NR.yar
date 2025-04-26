
rule VirTool_Win32_Obfuscator_NR{
	meta:
		description = "VirTool:Win32/Obfuscator.NR,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 b4 0f b7 40 06 39 45 a4 7d 41 8b 45 a4 6b c0 28 8b 4d b4 8d 84 01 f8 00 00 00 89 45 a0 8b 45 a0 8b 4d f4 03 48 14 89 4d ec 8b 45 a0 8b 4d d0 03 48 0c 89 4d c4 8b 45 a0 ff 70 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}