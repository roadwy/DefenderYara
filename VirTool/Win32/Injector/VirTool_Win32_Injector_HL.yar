
rule VirTool_Win32_Injector_HL{
	meta:
		description = "VirTool:Win32/Injector.HL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 07 0f 81 8d fe ff ff } //01 00 
		$a_01_1 = {72 78 0f 81 3e ff ff ff eb } //01 00 
		$a_01_2 = {39 f1 0f 81 aa 00 00 00 } //01 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}