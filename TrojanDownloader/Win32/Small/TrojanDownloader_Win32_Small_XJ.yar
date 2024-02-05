
rule TrojanDownloader_Win32_Small_XJ{
	meta:
		description = "TrojanDownloader:Win32/Small.XJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 56 57 8d 45 fc 68 1c 11 a0 2a 89 45 fc ff 15 10 10 a0 2a 8b 1d 44 10 a0 2a 68 00 11 a0 2a 50 ff d3 8d 4d f8 51 6a 04 ff 75 fc a3 44 22 a0 2a 6a 0b ff d0 3d 04 00 00 c0 } //01 00 
		$a_01_1 = {43 55 52 52 45 4e 54 5f 55 53 45 52 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 00 00 00 6e 74 64 6c 6c 00 00 00 4e 74 4f 70 65 6e 53 65 63 74 69 6f 6e 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_01_2 = {73 76 63 68 6f 73 74 2e 65 78 65 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29 } //00 00 
	condition:
		any of ($a_*)
 
}