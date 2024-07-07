
rule VirTool_Win32_Obfuscator_NT{
	meta:
		description = "VirTool:Win32/Obfuscator.NT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 7d 0c 11 11 11 11 75 12 c7 45 0c d4 70 81 03 8b 45 0c } //1
		$a_01_1 = {00 f2 36 df 05 7d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}