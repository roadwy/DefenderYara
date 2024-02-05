
rule TrojanDownloader_Win32_Adload_CN{
	meta:
		description = "TrojanDownloader:Win32/Adload.CN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 62 63 6a 6a 67 63 2e 63 6f 6d } //01 00 
		$a_01_1 = {20 4e 54 5c 73 6d 73 5f 6c 6f 67 2e 74 78 74 } //01 00 
		$a_01_2 = {5c 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 31 5c } //01 00 
		$a_01_3 = {65 64 6f 6e 6b 65 79 73 65 72 76 65 72 32 2e 38 38 30 30 2e 6f 72 67 2f 45 78 65 49 6e 69 2f } //01 00 
		$a_01_4 = {70 75 62 2e 68 79 67 61 6d 65 38 38 38 38 2e 63 6e 2f 63 38 63 5f 69 6e 69 2f 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}