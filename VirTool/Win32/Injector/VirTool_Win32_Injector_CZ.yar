
rule VirTool_Win32_Injector_CZ{
	meta:
		description = "VirTool:Win32/Injector.CZ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 cb c6 85 26 ff ff ff 6c c6 85 27 ff ff ff 6c c6 85 21 ff ff ff 74 c6 85 22 ff ff ff 75 c6 85 20 ff ff ff 72 } //01 00 
		$a_01_1 = {50 6a 00 ff d6 8b f0 e8 00 00 00 00 58 89 45 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}