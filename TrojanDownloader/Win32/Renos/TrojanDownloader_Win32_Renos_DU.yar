
rule TrojanDownloader_Win32_Renos_DU{
	meta:
		description = "TrojanDownloader:Win32/Renos.DU,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 00 00 00 00 eb 09 8b ?? fc 83 ?? 01 89 ?? fc 8b ?? fc 3b ?? f8 7d 16 8b ?? 08 03 ?? fc 0f be ?? 83 ?? ?? 8b ?? ?? 03 } //4
		$a_00_1 = {ff f1 50 30 b5 98 cf 11 bb } //1
		$a_01_2 = {6d 66 65 65 64 2e 70 68 70 3f 74 78 74 3d 31 26 61 66 66 69 6c 69 61 74 65 3d } //1 mfeed.php?txt=1&affiliate=
		$a_01_3 = {26 69 70 5f 61 64 64 72 65 73 73 3d } //1 &ip_address=
		$a_01_4 = {26 72 69 64 3d 30 26 73 74 3d 74 79 70 65 69 6e 26 72 65 66 3d } //1 &rid=0&st=typein&ref=
		$a_01_5 = {6b 2e 74 78 74 } //1 k.txt
		$a_01_6 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //1 /download.php
		$a_01_7 = {2f 62 75 79 2e 70 68 70 } //1 /buy.php
		$a_01_8 = {67 6f 6f 67 6c 65 2e 00 } //1 潧杯敬.
		$a_03_9 = {2f 70 72 65 66 65 72 65 6e 63 65 73 [0-08] 2f 61 64 76 61 6e 63 65 64 5f 73 65 61 72 63 68 [0-08] 26 71 3d [0-05] 3f 71 3d } //1
		$a_01_10 = {73 00 00 00 76 00 00 00 2e 65 00 00 78 00 00 00 65 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*1+(#a_01_10  & 1)*1) >=7
 
}