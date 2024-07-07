
rule VirTool_Win32_Obfuscator_AGW{
	meta:
		description = "VirTool:Win32/Obfuscator.AGW,SIGNATURE_TYPE_PEHSTR,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 43 6f 72 45 78 65 4d 61 69 6e } //1 _CorExeMain
		$a_01_1 = {04 20 ee 82 99 3c 20 82 00 20 d2 61 20 8e 06 96 0f 61 66 66 20 b7 1a c1 b7 61 66 20 db 7b e9 f7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}