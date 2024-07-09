
rule TrojanDownloader_Win32_Stegvob_E{
	meta:
		description = "TrojanDownloader:Win32/Stegvob.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 5d fc 83 c3 fa 3b fb 77 11 8b c6 3a 43 01 75 03 ff 53 02 83 eb 06 3b fb } //1
		$a_01_1 = {2e 00 72 00 75 00 2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 3f 00 73 00 65 00 61 00 72 00 63 00 68 00 3d 00 } //1 .ru/get.php?search=
		$a_03_2 = {25 00 63 00 25 00 73 00 [0-03] 3a 00 5c 00 50 00 68 00 6f 00 74 00 6f 00 2e 00 73 00 63 00 72 00 } //1
		$a_01_3 = {69 65 6c 6f 61 64 2e 6e 65 74 2f 6c 6f 61 64 2e 67 69 66 3f } //1 ieload.net/load.gif?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}