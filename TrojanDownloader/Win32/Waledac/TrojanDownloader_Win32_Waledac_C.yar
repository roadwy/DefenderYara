
rule TrojanDownloader_Win32_Waledac_C{
	meta:
		description = "TrojanDownloader:Win32/Waledac.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 54 65 6d 70 5c 5f 65 78 2d 00 00 2e 65 78 65 00 00 00 00 2f } //1
		$a_01_1 = {2f 63 6f 72 61 67 6f 61 32 5f 62 2e 65 78 65 } //1 /coragoa2_b.exe
		$a_01_2 = {2f 70 61 74 63 68 2e 65 78 65 } //1 /patch.exe
		$a_01_3 = {2f 6f 75 74 6c 6f 6f 6b 2e 65 78 65 } //1 /outlook.exe
		$a_03_4 = {68 00 a0 1f 00 e8 90 01 02 ff ff a3 90 01 04 c7 04 24 00 90 90 01 00 e8 90 00 } //2
		$a_01_5 = {84 c0 75 13 53 ff d7 ff 45 fc 83 7d fc 0a 7c bd } //2
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2+(#a_01_5  & 1)*2) >=4
 
}