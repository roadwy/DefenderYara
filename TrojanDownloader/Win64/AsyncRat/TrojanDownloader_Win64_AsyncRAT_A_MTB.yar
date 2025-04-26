
rule TrojanDownloader_Win64_AsyncRAT_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 6d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //2 C:\Users\Public\main.exe
		$a_01_1 = {3a 00 2f 00 2f 00 31 00 31 00 36 00 2e 00 36 00 32 00 2e 00 31 00 31 00 2e 00 39 00 30 00 2f 00 6d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //2 ://116.62.11.90/main.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}