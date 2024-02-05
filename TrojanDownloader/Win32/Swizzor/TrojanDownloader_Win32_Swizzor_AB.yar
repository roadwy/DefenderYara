
rule TrojanDownloader_Win32_Swizzor_AB{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.AB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 31 2e 69 6e 69 } //01 00 
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 4b 42 39 37 38 39 37 38 2e 6c 6f 67 } //01 00 
		$a_01_2 = {65 3a 5c 4a 69 6e 5a 51 5c } //01 00 
		$a_01_3 = {70 72 6f 63 65 73 73 31 00 70 72 6f 63 65 73 73 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Swizzor_AB_2{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.AB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 4b 42 39 37 38 39 37 38 2e 6c 6f 67 } //01 00 
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 31 2e 69 6e 69 } //01 00 
		$a_01_2 = {70 72 6f 63 65 73 73 31 00 70 72 6f 63 65 73 73 32 } //01 00 
		$a_01_3 = {61 62 6f 75 74 3a 62 6c 61 6e 6b 00 68 74 74 70 3a 2f 2f 73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e } //00 00 
	condition:
		any of ($a_*)
 
}