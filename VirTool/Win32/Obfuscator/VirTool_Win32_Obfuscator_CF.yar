
rule VirTool_Win32_Obfuscator_CF{
	meta:
		description = "VirTool:Win32/Obfuscator.CF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 40 00 00 00 [0-10] 8b ?? 3c 01 ?? 8b ?? 50 [0-08] ff [d0-d7] } //1
		$a_03_1 = {81 f8 00 7d 00 00 [0-10] 0f 83 ?? 00 00 00 [0-18] 80 fc 05 [0-10] 0f 83 ?? 00 00 00 [0-18] 81 f8 7f 00 00 00 [0-10] 0f 87 ?? 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}