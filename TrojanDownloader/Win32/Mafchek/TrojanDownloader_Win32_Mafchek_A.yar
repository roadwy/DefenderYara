
rule TrojanDownloader_Win32_Mafchek_A{
	meta:
		description = "TrojanDownloader:Win32/Mafchek.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 20 25 73 20 25 73 00 63 68 65 6b 00 68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 25 73 } //01 00 
		$a_01_3 = {2f 69 6d 61 67 65 73 2f 74 6f 70 32 78 2e 67 69 66 } //01 00 
		$a_01_4 = {49 20 72 75 6e 20 69 6e 20 69 6e 6a 65 63 74 65 64 20 70 72 6f 63 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}