
rule VirTool_Win32_Obfuscator_KQ{
	meta:
		description = "VirTool:Win32/Obfuscator.KQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f9 07 92 8e 2a 74 ?? 81 f9 da 12 44 ca 74 ?? 81 f9 83 e1 14 ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}