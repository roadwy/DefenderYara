
rule TrojanDownloader_BAT_Banload_P{
	meta:
		description = "TrojanDownloader:BAT/Banload.P,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {5f 64 6f 77 6e 4c 6f 61 64 46 69 6c 65 } //1 _downLoadFile
		$a_01_1 = {5f 66 69 6c 65 64 6f 77 6e } //1 _filedown
		$a_01_2 = {64 65 63 72 69 70 74 00 } //1 敤牣灩t
		$a_01_3 = {5f 53 51 4c 43 6f 6e 6e 00 } //1
		$a_01_4 = {5f 53 51 4c 43 6d 64 00 } //1 卟䱑浃d
		$a_03_5 = {06 0d 09 02 7b ?? 00 00 04 73 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 74 ?? 00 00 1b } //3
		$a_03_6 = {06 13 05 11 05 02 7b ?? 00 00 04 73 ?? 00 00 0a 13 04 11 04 6f ?? 00 00 0a 74 ?? 00 00 1b } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*3+(#a_03_6  & 1)*3) >=6
 
}
rule TrojanDownloader_BAT_Banload_P_2{
	meta:
		description = "TrojanDownloader:BAT/Banload.P,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 4c 6f 61 64 46 69 6c 65 00 } //1
		$a_01_1 = {64 65 63 72 69 70 74 00 } //1 敤牣灩t
		$a_01_2 = {5f 53 51 4c 43 6f 6e 6e 00 } //1
		$a_01_3 = {5f 53 51 4c 43 6d 64 00 } //1 卟䱑浃d
		$a_02_4 = {5c 62 61 69 78 61 90 05 06 08 72 6c 6f 61 64 30 2d 39 5c } //1
		$a_01_5 = {5c 64 6f 77 6e 6c 6f 61 64 6c 6f 69 61 64 5c 64 6f 77 6e 6c 6f 61 64 6c 6f 69 61 64 5c } //1 \downloadloiad\downloadloiad\
		$a_03_6 = {00 70 6f 2f 00 00 06 0d 09 02 7b ?? 00 00 04 73 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 74 0c 00 00 1b 0a 02 7b ?? 00 00 04 72 ?? ?? 00 70 90 09 09 00 02 7b ?? 00 00 04 72 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*2) >=5
 
}