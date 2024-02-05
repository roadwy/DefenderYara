
rule VirTool_Win32_Injector_gen_ER{
	meta:
		description = "VirTool:Win32/Injector.gen!ER,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e8 04 0f 6e 07 0f 6e ce 0f ef c1 0f 7e 07 83 c7 04 85 c0 75 ea } //00 00 
	condition:
		any of ($a_*)
 
}