
rule TrojanDownloader_WinNT_OpenStream_BK{
	meta:
		description = "TrojanDownloader:WinNT/OpenStream.BK,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 04 00 bc 08 90 02 30 02 9f 00 10 90 01 0a a7 ff e4 90 00 } //1
		$a_03_1 = {6e 65 74 2f 55 52 4c 90 02 18 59 6f 75 72 44 69 72 65 63 74 4c 69 6e 90 00 } //1
		$a_01_2 = {59 6f 75 72 46 69 6c 65 } //1 YourFile
		$a_01_3 = {01 00 04 47 6f 54 6f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}