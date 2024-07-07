
rule VirTool_Win32_Obfuscator_Pouletcrypt{
	meta:
		description = "VirTool:Win32/Obfuscator.Pouletcrypt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {00 80 00 00 29 90 01 02 6a 00 03 b3 90 01 03 00 56 2b b3 90 01 03 00 29 90 01 02 e8 90 01 01 00 00 00 5b 5e 5f 5a ff e3 90 00 } //1
		$a_00_1 = {59 d3 c0 8a dc b4 00 d3 cb 59 49 75 ea c1 cb 18 52 29 d2 31 da 89 d0 5a 5b 59 c9 c2 04 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}