
rule TrojanDownloader_Win32_Zlob_YU{
	meta:
		description = "TrojanDownloader:Win32/Zlob.YU,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {53 8a 5c 24 18 80 c3 64 2b fe 8a cb 32 c8 90 02 02 88 0e 6a 00 46 90 00 } //05 00 
		$a_01_1 = {68 00 01 00 00 53 53 53 ff 75 0c 8d 8d f0 fe ff ff 51 50 c6 85 f0 fe ff ff 47 c6 85 f1 fe ff ff 45 c6 85 f2 fe ff ff 54 88 9d f3 fe ff ff } //04 00 
		$a_01_2 = {00 5f 52 45 44 44 5f 00 } //04 00  开䕒䑄_
		$a_01_3 = {00 25 73 5c 7a 66 25 73 25 64 2e 65 78 65 00 } //04 00 
		$a_01_4 = {00 73 74 65 72 65 6f 00 } //04 00  猀整敲o
		$a_01_5 = {00 79 61 68 6f 6f 2e 00 00 67 6f 6f 67 6c 65 2e 00 } //00 00 
	condition:
		any of ($a_*)
 
}