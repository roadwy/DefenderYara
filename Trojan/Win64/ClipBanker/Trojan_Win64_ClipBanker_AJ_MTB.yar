
rule Trojan_Win64_ClipBanker_AJ_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 34 38 5d 5b 30 2d 39 41 42 5d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 39 33 7d } //2 [48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}
		$a_01_1 = {47 65 74 43 6c 69 70 62 6f 61 72 64 53 65 71 75 65 6e 63 65 4e 75 6d 62 65 72 } //2 GetClipboardSequenceNumber
		$a_01_2 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //2 SetClipboardData
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //2 GetClipboardData
		$a_01_4 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //2 EmptyClipboard
		$a_01_5 = {26 26 20 65 78 69 74 } //2 && exit
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}