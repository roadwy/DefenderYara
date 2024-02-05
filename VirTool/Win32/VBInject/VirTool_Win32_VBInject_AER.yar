
rule VirTool_Win32_VBInject_AER{
	meta:
		description = "VirTool:Win32/VBInject.AER,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 31 c1 81 f9 89 d8 89 d8 75 } //01 00 
		$a_01_1 = {40 31 c1 81 f9 89 d9 89 d9 75 } //02 00 
		$a_01_2 = {43 43 83 c3 02 81 7c 1d fc 4e 4e 4e 4e } //02 00 
		$a_01_3 = {43 83 c3 03 81 7c 1d fc 4c 4c 4c 4c 75 } //02 00 
		$a_01_4 = {43 83 c3 03 81 7c 1d fc 91 91 91 91 75 } //02 00 
		$a_01_5 = {43 83 c3 03 81 7c 1d fc 92 92 92 92 } //00 00 
		$a_00_6 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}