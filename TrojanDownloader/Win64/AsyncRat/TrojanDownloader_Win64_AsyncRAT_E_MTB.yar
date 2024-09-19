
rule TrojanDownloader_Win64_AsyncRAT_E_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 61 74 44 6f 77 6e 6c 6f 61 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 52 61 74 4c 6f 61 64 65 72 2e 70 64 62 } //4 RatDownload\x64\Release\RatLoader.pdb
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 2f 52 65 61 6c 65 61 73 65 } //2 download/Realease
		$a_01_2 = {41 50 50 44 41 54 41 } //2 APPDATA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=8
 
}