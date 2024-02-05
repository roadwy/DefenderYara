
rule Backdoor_Win32_Hupigon_ZAK{
	meta:
		description = "Backdoor:Win32/Hupigon.ZAK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 01 6a 47 68 90 01 04 89 45 90 01 01 ff d6 83 c4 0c 50 90 00 } //02 00 
		$a_00_1 = {30 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00 
		$a_00_2 = {47 54 5f 55 70 64 61 74 65 } //01 00 
		$a_00_3 = {5c 47 68 30 73 74 20 25 64 } //01 00 
		$a_00_4 = {25 73 3a 5c 44 6f 63 75 6d 65 6e 74 73 } //01 00 
		$a_00_5 = {4f 4e 53 5c 49 45 78 50 4c 6f 52 45 2e 45 58 45 5c 53 48 65 6c 4c 5c } //00 00 
	condition:
		any of ($a_*)
 
}