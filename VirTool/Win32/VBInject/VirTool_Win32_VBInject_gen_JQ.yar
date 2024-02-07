
rule VirTool_Win32_VBInject_gen_JQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!JQ,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 06 00 00 32 00 "
		
	strings :
		$a_01_0 = {68 d0 37 10 f2 } //32 00 
		$a_01_1 = {68 88 fe b3 16 } //0a 00 
		$a_01_2 = {76 62 61 53 74 72 56 61 72 4d 6f 76 65 } //01 00  vbaStrVarMove
		$a_03_3 = {b9 84 00 00 00 c7 85 90 01 04 c1 00 00 90 90 89 bd 90 01 04 2b 48 14 8d 95 90 01 04 c1 e1 04 90 00 } //01 00 
		$a_03_4 = {b9 85 00 00 00 2b 48 14 c1 e1 04 03 48 0c ff d6 8b 45 90 01 01 c7 85 90 01 04 0d 00 00 00 90 00 } //01 00 
		$a_03_5 = {b9 84 00 00 00 c7 85 90 01 04 c1 00 0d 00 c7 85 90 01 04 02 00 00 00 2b 48 14 8d 95 90 01 04 c1 e1 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}