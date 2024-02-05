
rule Backdoor_Win32_Drixed_I{
	meta:
		description = "Backdoor:Win32/Drixed.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 37 00 00 00 e8 90 01 04 89 44 90 01 02 b8 87 00 00 00 e8 90 01 04 89 44 90 01 02 b8 77 00 00 00 e8 90 00 } //01 00 
		$a_03_1 = {b8 83 00 00 00 89 8c 90 01 05 e8 90 01 04 6a 40 68 00 30 00 00 68 60 28 00 00 6a 00 ff d0 90 00 } //01 00 
		$a_03_2 = {6a 36 58 e8 90 01 04 6a 00 ff 33 ff d0 eb 90 00 } //00 00 
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}