
rule VirTool_Win32_VBInject_gen_LL{
	meta:
		description = "VirTool:Win32/VBInject.gen!LL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 52 00 45 00 65 00 42 00 2e 00 76 00 62 00 70 00 } //01 00  \REeB.vbp
		$a_01_1 = {5c 00 66 00 66 00 7a 00 65 00 66 00 7a 00 65 00 66 00 7a 00 2e 00 76 00 62 00 70 00 } //01 00  \ffzefzefz.vbp
		$a_01_2 = {5c 00 67 00 75 00 67 00 75 00 2e 00 76 00 62 00 70 00 } //00 00  \gugu.vbp
	condition:
		any of ($a_*)
 
}