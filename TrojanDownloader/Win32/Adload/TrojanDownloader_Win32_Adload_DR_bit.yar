
rule TrojanDownloader_Win32_Adload_DR_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 33 2d 75 73 2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 65 6c 61 73 74 69 63 62 65 61 6e 73 74 61 6c 6b 2d 75 73 2d 77 65 73 74 2d 32 2d 31 34 33 36 39 32 34 36 38 38 37 32 2f 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //01 00 
		$a_03_1 = {6d 79 66 69 6c 65 73 64 6f 77 6e 6c 6f 61 64 2e 63 6f 6d 2f 90 02 40 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Adload_DR_bit_2{
	meta:
		description = "TrojanDownloader:Win32/Adload.DR!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 ec 1c 8b cc 89 a5 cc fe ff ff 68 90 01 04 e8 90 01 04 e8 90 01 04 8b cc 89 a5 cc fe ff ff 68 90 01 04 e8 90 01 04 e8 90 00 } //03 00 
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 65 00 61 00 64 00 6c 00 65 00 6e 00 74 00 61 00 2e 00 72 00 75 00 2f 00 90 02 10 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 64 00 61 00 6e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 90 02 10 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_03_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 63 00 6c 00 65 00 76 00 65 00 72 00 61 00 64 00 64 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 90 02 10 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}