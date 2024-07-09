
rule VirTool_Win32_Obfuscator_APA{
	meta:
		description = "VirTool:Win32/Obfuscator.APA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d2 ab e2 [a0-c0] 61 c9 c2 10 00 55 89 e5 56 51 57 } //1
		$a_03_1 = {e8 00 00 00 00 5b [0[ 06 [70-7] f] 04 [0[ 06 [70-7] f] 04 [0-7f] 64 a1 30 00 00 [ 83 ?? ??]  00 00 50 ff[ 00] } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}