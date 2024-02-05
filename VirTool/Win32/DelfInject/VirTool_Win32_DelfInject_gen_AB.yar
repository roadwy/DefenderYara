
rule VirTool_Win32_DelfInject_gen_AB{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 34 1f 32 8b c6 34 01 32 04 1f 34 00 34 01 34 32 88 04 1f } //00 00 
	condition:
		any of ($a_*)
 
}