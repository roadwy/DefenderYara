
rule VirTool_Win32_Obfuscator_TV{
	meta:
		description = "VirTool:Win32/Obfuscator.TV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f3 a5 66 a5 a4 eb 90 01 01 90 04 01 03 8b ff 8f 90 02 08 83 c0 01 90 02 10 0f 73 90 01 01 6a 06 6a 00 6a 00 6a 00 68 c0 12 90 03 01 01 40 00 90 03 01 01 10 00 ff 15 90 01 04 ff 15 90 01 04 83 f8 57 74 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}