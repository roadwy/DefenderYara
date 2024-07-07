
rule VirTool_Win32_Obfuscator_XV{
	meta:
		description = "VirTool:Win32/Obfuscator.XV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 ab aa 8b 3d 90 01 04 8d 45 ec 50 ff d7 8b 75 f8 81 e6 ff ff 00 00 83 fe 31 7e 05 83 ee 32 eb 03 83 c6 0a 8d 4d ec 51 ff d7 8b 55 f8 81 e2 ff ff 00 00 3b d6 75 ed 68 00 2e 00 00 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}