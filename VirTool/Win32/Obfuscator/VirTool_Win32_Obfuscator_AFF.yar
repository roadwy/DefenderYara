
rule VirTool_Win32_Obfuscator_AFF{
	meta:
		description = "VirTool:Win32/Obfuscator.AFF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 6a 40 6a 05 50 ff 55 fc 85 c0 74 3f a1 90 01 04 8a 08 8b 7d f8 88 0d 90 01 04 8b 48 01 89 0d 90 01 04 c6 00 e9 a1 90 01 04 b9 90 01 04 2b c8 83 e9 05 68 90 01 04 89 48 01 e8 90 01 04 59 8d 4d 90 01 01 51 ff d0 5f 5e 33 c0 c9 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}