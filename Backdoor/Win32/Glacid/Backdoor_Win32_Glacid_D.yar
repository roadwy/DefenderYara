
rule Backdoor_Win32_Glacid_D{
	meta:
		description = "Backdoor:Win32/Glacid.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 44 4f 57 4e 45 58 3e } //01 00 
		$a_01_1 = {3c 44 4f 57 4e 3e } //01 00 
		$a_01_2 = {3c 53 54 4f 50 3e } //01 00 
		$a_01_3 = {3c 44 45 4c 41 59 3e } //01 00 
		$a_01_4 = {53 65 72 76 65 72 2d 43 6f 6d 6d 61 6e 64 3a 20 } //01 00 
		$a_01_5 = {6e 65 74 20 73 74 6f 70 20 25 73 20 26 20 73 63 20 64 65 6c 65 74 65 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}