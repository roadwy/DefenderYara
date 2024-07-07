
rule TrojanDownloader_Win32_Renos_DG{
	meta:
		description = "TrojanDownloader:Win32/Renos.DG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d f8 7d 18 8b 55 08 03 55 fc 0f be 02 35 90 01 01 00 00 00 8b 4d 0c 03 4d fc 88 01 eb d7 90 00 } //2
		$a_03_1 = {83 f8 06 0f 85 90 01 02 00 00 68 90 01 04 e8 90 01 02 00 00 83 c4 04 89 90 03 01 01 45 85 90 09 1f 00 6a 00 ff 15 90 01 02 00 10 90 00 } //2
		$a_01_2 = {76 65 72 69 66 69 65 64 70 61 79 6d 65 6e 74 73 6f 6c 75 74 69 6f 6e 73 6f 6e 6c 69 6e 65 } //1 verifiedpaymentsolutionsonline
		$a_01_3 = {3f 73 6b 75 5f 6e 61 6d 65 3d } //1 ?sku_name=
		$a_01_4 = {6d 66 65 65 64 2e 70 68 70 3f 74 78 74 3d 31 26 61 66 66 69 6c 69 61 74 65 3d } //1 mfeed.php?txt=1&affiliate=
		$a_01_5 = {72 69 64 3d 30 26 73 74 3d 74 79 70 65 69 6e 26 72 65 66 3d } //1 rid=0&st=typein&ref=
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}