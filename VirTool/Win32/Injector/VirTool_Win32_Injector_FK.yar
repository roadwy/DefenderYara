
rule VirTool_Win32_Injector_FK{
	meta:
		description = "VirTool:Win32/Injector.FK,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {68 13 8e c0 09 50 e8 90 01 02 00 00 8b 4d 90 01 01 68 ee 38 83 0c 51 a3 90 01 02 40 00 e8 90 01 02 00 00 68 f2 5d d3 0b 90 00 } //01 00 
		$a_01_1 = {68 99 b0 48 06 } //01 00 
		$a_01_2 = {68 44 27 23 0f } //01 00 
		$a_00_3 = {68 57 64 e1 01 } //01 00 
		$a_00_4 = {68 ac 6f bc 06 } //01 00 
		$a_00_5 = {68 e3 ca d8 03 } //01 00 
		$a_00_6 = {68 05 d1 3d 0b } //00 00 
	condition:
		any of ($a_*)
 
}