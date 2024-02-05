
rule VirTool_Win32_DelfInject_gen_CB{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {67 3f 5f 73 6d 6b 67 6b 73 76 5f 77 7d 76 77 61 69 36 31 58 77 64 6e 74 68 60 5c 35 2a 60 7b 61 } //03 00 
		$a_01_1 = {55 8b ec 51 0f 00 45 fe 0f b7 45 fe 0d 00 00 ad de 59 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}