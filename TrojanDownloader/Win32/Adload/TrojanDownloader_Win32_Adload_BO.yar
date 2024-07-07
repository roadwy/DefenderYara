
rule TrojanDownloader_Win32_Adload_BO{
	meta:
		description = "TrojanDownloader:Win32/Adload.BO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {59 ff 45 fc 81 7d fc e8 03 00 00 7d 4b 83 3d 90 01 04 00 75 42 68 30 75 00 00 ff 15 90 01 04 eb 80 e8 90 01 04 6a 0c 90 00 } //1
		$a_03_1 = {68 d0 07 00 00 ff 15 90 01 04 83 fe 04 75 01 90 90 81 fe 08 07 00 00 75 01 90 90 46 83 7d fc 00 0f 85 90 01 04 33 c0 5e c9 c2 10 00 83 c8 ff eb f6 90 00 } //1
		$a_01_2 = {2e 6e 69 75 64 6f 75 64 6f 75 2e 63 6f 6d 2f 77 65 62 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 .niudoudou.com/web/download/
		$a_03_3 = {67 65 74 5f 61 64 90 02 01 2e 61 73 70 3f 74 79 70 65 3d 6c 6f 61 64 61 6c 6c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}