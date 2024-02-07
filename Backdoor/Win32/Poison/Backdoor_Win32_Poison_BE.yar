
rule Backdoor_Win32_Poison_BE{
	meta:
		description = "Backdoor:Win32/Poison.BE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 64 3d 00 34 31 2e 70 68 70 3f 00 47 45 54 00 63 6d 64 20 } //01 00 
		$a_01_1 = {33 31 2e 70 68 70 3f 00 43 72 65 61 74 65 20 70 72 6f 63 65 73 73 20 66 61 69 6c 21 00 } //02 00 
		$a_01_2 = {6a 04 8d 44 24 14 50 6a 06 bb 30 75 00 00 55 89 5c 24 20 ff d6 6a 04 8d 4c 24 14 51 6a 05 55 89 5c 24 20 ff d6 6a 00 6a 00 6a 03 6a 00 6a 00 6a 50 57 55 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Poison_BE_2{
	meta:
		description = "Backdoor:Win32/Poison.BE,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 64 3d 25 73 26 69 64 3d 25 73 26 69 64 3d 25 73 26 69 64 3d 25 73 26 69 64 3d 25 73 26 69 64 3d 25 73 } //02 00  id=%s&id=%s&id=%s&id=%s&id=%s&id=%s
		$a_01_1 = {5c 77 69 6e 2e 69 6e 69 00 00 00 00 63 6f 6f 6b 69 65 73 5c } //02 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 00 50 4f 53 54 00 00 00 00 69 64 3d 00 34 31 2e 70 68 70 3f } //01 00 
		$a_01_3 = {4f 70 65 6e 20 48 4f 53 54 5f 55 52 4c 20 65 72 72 6f 72 } //01 00  Open HOST_URL error
		$a_01_4 = {56 53 54 25 64 2e 25 64 2e 25 64 2e 25 73 } //00 00  VST%d.%d.%d.%s
	condition:
		any of ($a_*)
 
}