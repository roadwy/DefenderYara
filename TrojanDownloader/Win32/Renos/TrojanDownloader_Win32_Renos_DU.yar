
rule TrojanDownloader_Win32_Renos_DU{
	meta:
		description = "TrojanDownloader:Win32/Renos.DU,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 04 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 00 00 00 00 eb 09 8b 90 01 01 fc 83 90 01 01 01 89 90 01 01 fc 8b 90 01 01 fc 3b 90 01 01 f8 7d 16 8b 90 01 01 08 03 90 01 01 fc 0f be 90 01 01 83 90 01 02 8b 90 01 02 03 90 00 } //01 00 
		$a_00_1 = {ff f1 50 30 b5 98 cf 11 bb } //01 00 
		$a_01_2 = {6d 66 65 65 64 2e 70 68 70 3f 74 78 74 3d 31 26 61 66 66 69 6c 69 61 74 65 3d } //01 00  mfeed.php?txt=1&affiliate=
		$a_01_3 = {26 69 70 5f 61 64 64 72 65 73 73 3d } //01 00  &ip_address=
		$a_01_4 = {26 72 69 64 3d 30 26 73 74 3d 74 79 70 65 69 6e 26 72 65 66 3d } //01 00  &rid=0&st=typein&ref=
		$a_01_5 = {6b 2e 74 78 74 } //01 00  k.txt
		$a_01_6 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //01 00  /download.php
		$a_01_7 = {2f 62 75 79 2e 70 68 70 } //01 00  /buy.php
		$a_01_8 = {67 6f 6f 67 6c 65 2e 00 } //01 00  潧杯敬.
		$a_03_9 = {2f 70 72 65 66 65 72 65 6e 63 65 73 90 02 08 2f 61 64 76 61 6e 63 65 64 5f 73 65 61 72 63 68 90 02 08 26 71 3d 90 02 05 3f 71 3d 90 00 } //01 00 
		$a_01_10 = {73 00 00 00 76 00 00 00 2e 65 00 00 78 00 00 00 65 } //00 00 
	condition:
		any of ($a_*)
 
}