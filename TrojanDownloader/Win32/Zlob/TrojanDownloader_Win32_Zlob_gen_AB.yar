
rule TrojanDownloader_Win32_Zlob_gen_AB{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff9b 01 ffffff9b 01 09 00 00 64 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //64 00 
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //64 00 
		$a_01_2 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //64 00 
		$a_00_3 = {44 69 73 70 6c 61 79 49 63 6f 6e } //0a 00 
		$a_01_4 = {74 6d 78 78 78 68 2e 64 6c 6c } //0a 00 
		$a_00_5 = {62 6c 6f 77 6a 6f 62 2e } //01 00 
		$a_01_6 = {73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //01 00 
		$a_01_7 = {56 69 72 75 73 } //01 00 
		$a_01_8 = {69 6e 66 65 63 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Zlob_gen_AB_2{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff9b 01 ffffff9b 01 09 00 00 64 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //64 00 
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //64 00 
		$a_01_2 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //64 00 
		$a_00_3 = {44 69 73 70 6c 61 79 49 63 6f 6e } //0a 00 
		$a_02_4 = {61 6e 61 6c 90 02 0a 6d 6f 6e 73 74 65 72 73 2e 63 6f 6d 90 00 } //0a 00 
		$a_01_5 = {2f 6d 61 74 75 72 65 2e 5f 78 65 } //01 00 
		$a_01_6 = {73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //01 00 
		$a_01_7 = {56 69 72 75 73 } //01 00 
		$a_01_8 = {69 6e 66 65 63 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}