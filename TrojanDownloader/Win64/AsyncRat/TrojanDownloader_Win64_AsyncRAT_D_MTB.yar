
rule TrojanDownloader_Win64_AsyncRAT_D_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6d 61 69 6e 90 01 01 2e 65 78 65 90 00 } //2
		$a_01_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 57 } //1 CreateProcessW
		$a_01_2 = {52 74 6c 47 65 74 4e 74 56 65 72 73 69 6f 6e 4e 75 6d 62 65 72 73 } //1 RtlGetNtVersionNumbers
		$a_03_3 = {2f 6d 61 69 6e 90 01 01 2e 65 78 65 90 00 } //2
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=5
 
}