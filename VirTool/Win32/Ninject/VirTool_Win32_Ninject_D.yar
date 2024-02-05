
rule VirTool_Win32_Ninject_D{
	meta:
		description = "VirTool:Win32/Ninject.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 10 8b 85 90 01 04 30 94 28 90 01 04 8b 85 90 01 04 ff 85 90 00 } //01 00 
		$a_03_1 = {8a 00 32 02 88 c2 8b 85 90 01 04 03 85 90 01 18 99 f7 bd 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}