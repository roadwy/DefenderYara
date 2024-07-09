
rule TrojanDownloader_Win32_Cutwail_BT{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 33 8b 4b 04 83 e9 08 83 c3 08 0f b7 03 a9 00 30 00 00 74 ?? 25 ff 0f 00 00 03 45 08 03 c6 29 10 83 c3 02 83 e9 02 } //1
		$a_03_1 = {ff 75 fc e8 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 8b 46 28 90 05 08 02 90 (90 05 08 02 90 90 ff d0 |)} //1
		$a_03_2 = {8b 75 08 03 76 3c (6a|eb 90 14 6a) 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 55 f0 } //1
		$a_00_3 = {34 31 33 30 74 35 67 69 6f 31 33 34 38 35 } //1 4130t5gio13485
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}