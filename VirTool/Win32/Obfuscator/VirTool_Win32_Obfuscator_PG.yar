
rule VirTool_Win32_Obfuscator_PG{
	meta:
		description = "VirTool:Win32/Obfuscator.PG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {81 a0 00 00 00 03 c7 8b 51 34 8b b1 a4 00 00 00 74 90 01 01 85 f6 74 90 00 01 } //1
		$a_8b_1 = {08 51 e8 90 01 04 8b 55 f4 89 15 44 43 40 00 5f 5e 5d 5b } //12544
	condition:
		((#a_13_0  & 1)*1+(#a_8b_1  & 1)*12544) >=2
 
}