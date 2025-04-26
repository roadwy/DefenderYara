
rule VirTool_Win32_Obfuscator_AIF{
	meta:
		description = "VirTool:Win32/Obfuscator.AIF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 75 ef c6 45 e6 53 c6 45 e7 65 c6 45 e8 74 c6 45 e9 50 c6 45 ea 69 c6 45 eb 78 c6 45 ec 65 c6 45 ed 6c c6 45 ee 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}