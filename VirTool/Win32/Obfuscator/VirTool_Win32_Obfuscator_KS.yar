
rule VirTool_Win32_Obfuscator_KS{
	meta:
		description = "VirTool:Win32/Obfuscator.KS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 02 59 5a 01 c1 83 c2 01 81 fa 00 ba 04 00 75 ?? 89 ce 8d 55 ?? 52 ff 94 1e 00 46 fb ff } //1
		$a_03_1 = {8b 06 83 c6 04 eb 90 14 2d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}