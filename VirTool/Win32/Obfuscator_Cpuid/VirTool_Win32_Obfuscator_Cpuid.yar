
rule VirTool_Win32_Obfuscator_Cpuid{
	meta:
		description = "VirTool:Win32/Obfuscator_Cpuid,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f a2 3d f6 06 00 00 75 ?? 81 f9 9c e1 00 00 75 ?? 81 fa ff fb eb bf 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}