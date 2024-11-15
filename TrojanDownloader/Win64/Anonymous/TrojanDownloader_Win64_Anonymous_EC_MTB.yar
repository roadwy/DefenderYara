
rule TrojanDownloader_Win64_Anonymous_EC_MTB{
	meta:
		description = "TrojanDownloader:Win64/Anonymous.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_81_0 = {6c 68 67 7a 6b 78 6b 2d 31 2d 31 33 32 36 31 30 31 30 32 38 2e 63 6f 73 2e 61 70 2d 63 68 65 6e 67 64 75 2e 6d 79 71 63 6c 6f 75 64 2e 63 6f 6d 2f 6c 61 64 68 7a 6a 78 61 2e 70 6e 67 } //5 lhgzkxk-1-1326101028.cos.ap-chengdu.myqcloud.com/ladhzjxa.png
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 41 67 65 6e 74 } //1 DownloadAgent
		$a_81_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_81_3 = {25 73 5c 32 30 32 34 2e 70 6e 67 } //1 %s\2024.png
		$a_81_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_81_5 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}