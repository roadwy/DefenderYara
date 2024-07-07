
rule VirTool_Win32_Obfuscator_PY{
	meta:
		description = "VirTool:Win32/Obfuscator.PY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 00 c7 44 24 04 8b 0d 90 01 04 89 48 04 c6 40 08 68 8b 0d 90 01 04 89 48 09 b1 c3 90 00 } //1
		$a_03_1 = {03 42 3c 89 45 90 01 01 8b 4d 90 01 01 8b 51 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}