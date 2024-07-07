
rule VirTool_Win32_Obfuscator_ABY{
	meta:
		description = "VirTool:Win32/Obfuscator.ABY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 18 03 c3 8b ce c1 e9 18 32 d1 47 81 ff 20 a1 07 00 88 10 7c c5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}