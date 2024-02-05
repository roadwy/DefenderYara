
rule TrojanDownloader_Win32_Genuyf_A{
	meta:
		description = "TrojanDownloader:Win32/Genuyf.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 73 65 72 33 32 2e 64 6c 6c 00 4c 6f 61 64 52 65 6d 6f 74 65 46 6f 6e 74 73 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 00 68 74 74 70 3a 2f 2f 63 6e 2e 63 6f 6d 2e 66 65 6e 67 79 75 6e 66 7a 2e 63 6f 6d 2e 63 6e 2f 69 6d 61 67 65 73 2f 69 6d 61 67 65 73 2f 64 6f 77 6e 2e 74 78 74 } //01 00 
		$a_02_1 = {81 c4 e8 fd ff ff 33 c0 89 90 01 02 6a 00 6a 00 6a 00 6a 00 68 90 01 02 40 00 e8 90 01 02 00 00 0b c0 0f 84 90 01 01 00 00 00 89 90 01 02 6a 04 ff 75 90 01 01 6a 02 ff 75 90 01 01 e8 90 01 02 00 00 6a 04 ff 75 90 01 01 6a 06 ff 75 90 01 01 e8 90 01 02 00 00 6a 00 68 00 00 20 00 6a 00 6a 00 ff 75 90 01 01 ff 75 90 01 01 e8 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}