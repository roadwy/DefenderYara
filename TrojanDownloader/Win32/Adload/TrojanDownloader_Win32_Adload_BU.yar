
rule TrojanDownloader_Win32_Adload_BU{
	meta:
		description = "TrojanDownloader:Win32/Adload.BU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c4 14 68 59 02 00 00 ff d5 68 93 01 00 00 ff d5 68 90 01 09 83 c4 04 84 c0 90 00 } //1
		$a_01_1 = {7e 31 5c 73 75 6f 79 6f 75 78 69 6e 73 2e 62 61 74 } //1 ~1\suoyouxins.bat
		$a_01_2 = {7e 31 5c 68 61 6f 79 72 75 2e 74 78 74 20 79 75 69 65 69 65 2e 65 78 65 } //1 ~1\haoyru.txt yuieie.exe
		$a_01_3 = {70 64 2e 6e 61 74 61 6e 6c 6d 2e 63 6e 2f 78 30 36 30 36 2f } //1 pd.natanlm.cn/x0606/
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}