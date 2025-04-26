
rule VirTool_Win32_Obfuscator_QC{
	meta:
		description = "VirTool:Win32/Obfuscator.QC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 0a 80 f1 ?? 80 (c1|e9) ?? 88 08 40 42 8a 0a 84 c9 } //1
		$a_03_1 = {6a 00 6a 14 8d 4d ?? 51 ff d0 (eb|e9) } //1
		$a_01_2 = {8b 4d f4 8b 11 33 d6 03 d7 3b c2 0f 82 92 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}