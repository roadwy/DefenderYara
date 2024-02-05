
rule TrojanDownloader_Win32_Adload_BZ{
	meta:
		description = "TrojanDownloader:Win32/Adload.BZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 73 40 6f 2b 6d 2a 5e 2b 2b 2a 61 5e 2b 63 40 6b 24 3d 2b 6d 2a 5e 2b 2b 2a 61 5e 2b 24 31 } //01 00 
		$a_01_1 = {3f 62 6e 24 3d 2b 2a 61 5e 2b 30 40 2b 6d 2a 5e 2b 26 71 40 79 3d } //01 00 
		$a_01_2 = {6c 6f 2b 6d 2a 5e 2b 63 61 74 69 2b 6d 2a 5e 2b 6f 6e 2e 72 65 70 2b 6d 2a 5e 2b 6c 61 63 65 28 } //01 00 
		$a_01_3 = {73 69 24 64 40 2b 6d 2a 5e 2b 65 62 2b 2a 61 5e 2b 40 61 72 5f 63 6c 2b 6d 2a 5e 2b 40 69 2b 2a 61 5e 2b 40 63 6b 24 2e 61 2b 2a 61 5e 2b 40 73 70 } //01 00 
		$a_01_4 = {6f 40 76 2b 2a 61 5e 2b 2b 6d 2a 5e 2b 65 24 72 74 40 6c 24 32 2e 63 24 2b 2a 61 5e 2b 2b 6d 2a 5e 2b 6f 40 6d 2f 40 6f 2b 2a 61 5e 2b 2b 6d 2a 5e 2b 24 73 6c 24 32 2f 6f 40 76 6e 2b 6d 2a 5e 2b 40 5f 6f 2e 61 40 73 70 } //00 00 
	condition:
		any of ($a_*)
 
}