
rule TrojanDownloader_Win32_Couly_A{
	meta:
		description = "TrojanDownloader:Win32/Couly.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 75 6c 79 2e 63 6f 6d 2f 76 69 73 69 74 2e 70 68 70 } //01 00 
		$a_01_1 = {63 6f 75 6c 79 2e 63 6f 6d 2f 75 70 64 61 74 65 2e 65 78 65 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_3 = {64 61 74 61 2e 61 6c 65 78 61 2e 63 6f 6d } //01 00 
		$a_01_4 = {62 6f 74 47 6f 57 61 79 } //01 00 
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}