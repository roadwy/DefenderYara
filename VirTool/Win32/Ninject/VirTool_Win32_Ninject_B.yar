
rule VirTool_Win32_Ninject_B{
	meta:
		description = "VirTool:Win32/Ninject.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 11 8b 95 90 01 04 30 84 15 90 01 04 ff 85 90 00 } //01 00 
		$a_03_1 = {8a 04 11 8b 55 90 01 01 8b 8d 90 01 04 30 04 0a ff 85 90 01 04 8b 85 90 01 04 99 f7 bd 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}