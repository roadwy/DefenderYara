
rule TrojanDownloader_Win32_Banload_PE{
	meta:
		description = "TrojanDownloader:Win32/Banload.PE,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {8d 95 f0 fb ff ff b9 00 04 00 00 8b c6 8b 18 ff 53 0c 8b d8 85 db 74 10 8d 95 f0 fb ff ff 8b cb 8b 45 f0 8b 38 ff 57 10 85 db 7f d4 } //01 00 
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 68 75 6e 74 65 72 } //01 00 
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 69 65 70 6c 6f 72 65 72 69 74 61 75 2e 6a 73 } //01 00 
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 63 74 66 72 6d 6f 6e 2e 65 78 65 } //01 00 
		$a_03_4 = {2e 63 6f 6d 2e 62 72 2f 90 02 0c 2e 6a 73 90 00 } //01 00 
		$a_03_5 = {2e 63 6f 6d 2e 62 72 2f 90 02 0c 2e 6a 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}