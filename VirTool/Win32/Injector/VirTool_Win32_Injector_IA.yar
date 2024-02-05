
rule VirTool_Win32_Injector_IA{
	meta:
		description = "VirTool:Win32/Injector.IA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 50 c6 45 90 01 01 6d c6 45 90 01 01 79 c6 45 90 01 01 61 c6 45 90 01 01 70 c6 45 90 01 01 70 c6 45 90 01 01 2e c6 45 90 01 01 65 c6 45 90 01 01 78 c6 45 90 01 01 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}