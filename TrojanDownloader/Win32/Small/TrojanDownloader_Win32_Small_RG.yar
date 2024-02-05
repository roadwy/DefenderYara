
rule TrojanDownloader_Win32_Small_RG{
	meta:
		description = "TrojanDownloader:Win32/Small.RG,SIGNATURE_TYPE_PEHSTR,21 00 21 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {26 76 65 72 3d 00 00 00 63 6c 63 6f 75 6e 74 2f 63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d 00 00 47 4f 4f 47 4c 45 } //01 00 
		$a_01_1 = {53 6b 79 4d 6f 6e 2e 65 78 65 } //01 00 
		$a_01_2 = {41 4c 59 61 63 2e 61 79 65 } //01 00 
		$a_01_3 = {41 79 41 67 65 6e 74 2e 61 79 65 } //01 00 
		$a_01_4 = {5c 73 79 73 74 65 6d 49 6e 66 6f 2e 69 6e 69 } //0a 00 
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00 
		$a_01_6 = {44 4c 4c 2e 64 6c 6c 00 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}