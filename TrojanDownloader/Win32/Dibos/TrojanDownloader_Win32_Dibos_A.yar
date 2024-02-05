
rule TrojanDownloader_Win32_Dibos_A{
	meta:
		description = "TrojanDownloader:Win32/Dibos.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 6c 65 74 73 5c 53 63 61 6e 64 69 73 6b 5c } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 66 69 72 65 77 61 6c 6c } //01 00 
		$a_01_2 = {73 79 73 74 65 6d 2e 65 78 65 } //01 00 
		$a_01_3 = {64 62 73 2e 64 61 74 } //01 00 
		$a_01_4 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //00 00 
	condition:
		any of ($a_*)
 
}