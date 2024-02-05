
rule VirTool_Win32_Injector_FL{
	meta:
		description = "VirTool:Win32/Injector.FL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 f6 21 20 21 20 81 c6 11 10 11 10 89 30 83 c0 04 83 ea 01 75 e7 } //01 00 
		$a_03_1 = {67 42 79 44 c7 90 01 02 75 60 40 7f c7 90 01 02 73 75 43 43 c7 90 01 02 1d 75 7d 7f c7 90 01 02 40 49 ce cf c7 90 01 02 ce cf cf cf e8 90 00 } //00 00 
		$a_00_2 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}