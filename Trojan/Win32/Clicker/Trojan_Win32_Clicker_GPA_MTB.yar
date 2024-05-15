
rule Trojan_Win32_Clicker_GPA_MTB{
	meta:
		description = "Trojan:Win32/Clicker.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 d2 8d 44 24 14 89 54 24 04 8d 4c 24 04 89 54 24 08 50 89 54 24 10 51 89 54 24 18 66 c7 44 24 0c 34 08 } //01 00 
		$a_81_1 = {4d 61 6c 73 65 72 76 69 63 65 } //01 00  Malservice
		$a_81_2 = {48 47 4c 33 34 35 } //00 00  HGL345
	condition:
		any of ($a_*)
 
}