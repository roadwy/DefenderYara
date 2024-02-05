
rule TrojanDownloader_Win32_Small_HD{
	meta:
		description = "TrojanDownloader:Win32/Small.HD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 63 61 63 6c 73 20 25 73 20 2f 65 20 2f 70 20 65 76 65 72 79 6f 6e 65 3a 66 } //01 00 
		$a_01_1 = {6b 69 6c 6c 72 64 6f 67 00 00 00 00 6b 69 6c 6c 65 72 64 6f 67 00 00 00 6b 69 6c 6c 64 6f 67 } //01 00 
		$a_00_2 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //01 00 
		$a_01_3 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c 6d 73 6f 65 72 65 73 32 2e 64 6c 6c } //01 00 
		$a_00_4 = {57 69 6e 45 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}