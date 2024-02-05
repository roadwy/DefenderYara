
rule TrojanDownloader_Win32_Banload_ES{
	meta:
		description = "TrojanDownloader:Win32/Banload.ES,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 77 77 77 2e 63 6f 72 72 65 69 6f 73 2e 63 6f 6d 2e 62 72 00 ff ff ff ff 33 00 00 00 68 74 74 70 3a 2f 2f 62 6f 78 73 74 72 2e 63 6f 6d 2f 66 69 6c 65 73 2f 31 33 39 35 39 33 39 5f 73 6a 69 67 69 2f 74 65 6c 65 67 72 61 6d 61 2e 65 78 65 00 ff ff ff ff 15 00 00 00 63 3a 5c 54 65 6d 70 5c 74 65 6c 65 67 72 61 6d 61 2e 65 78 65 00 00 00 00 00 00 00 43 3a 5c 54 65 6d 70 5c 74 65 6c 65 67 72 61 6d 61 2e 65 78 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}