
rule VirTool_Win32_Obfuscator_DA{
	meta:
		description = "VirTool:Win32/Obfuscator.DA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 01 00 00 00 c3 c3 60 8b 74 24 24 8b 7c 24 28 fc b2 80 33 db a4 } //1
		$a_01_1 = {03 c2 ff e0 b1 15 00 00 60 e8 00 00 00 00 5e 83 ee 0a 8b 06 03 c2 8b 08 89 4e f3 83 ee 0f 56 52 8b f0 ad ad 03 c2 8b d8 6a 04 bf 00 10 00 00 57 57 6a 00 ff 53 08 5a 59 bd 00 80 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}