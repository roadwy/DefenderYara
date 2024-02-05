
rule VirTool_Win32_VBInject_AES{
	meta:
		description = "VirTool:Win32/VBInject.AES,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {40 31 c1 81 f9 85 c0 85 c0 75 } //01 00 
		$a_01_1 = {43 43 83 c3 02 81 7c 1d fc 43 43 43 43 0f 85 } //01 00 
		$a_01_2 = {43 43 83 c3 02 81 7c 1d fc 43 43 43 43 75 } //01 00 
		$a_01_3 = {31 c2 89 54 1d 00 83 c3 04 81 7c 1d fc 43 43 43 43 75 } //01 00 
		$a_01_4 = {31 c2 89 54 1d 00 83 c3 04 81 7c 1d fc 42 42 42 42 75 } //00 00 
		$a_00_5 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}