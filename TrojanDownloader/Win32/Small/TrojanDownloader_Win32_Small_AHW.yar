
rule TrojanDownloader_Win32_Small_AHW{
	meta:
		description = "TrojanDownloader:Win32/Small.AHW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 06 32 da 88 18 40 4d 75 f5 } //1
		$a_01_1 = {53 75 70 70 65 72 54 4d 00 00 00 00 53 6f 66 74 77 61 72 65 5c 41 44 00 } //1
		$a_01_2 = {4e 65 66 6b 68 65 55 3c 3e 38 48 4d 3d 3d 31 24 38 4f 3f 30 24 3d 3e 6d 3c 24 48 4c 4a 38 24 4d 3c 4c 48 3b 3b 3a 3d 3d 39 30 4b } //1 NefkheU<>8HM==1$8O?0$=>m<$HLJ8$M<LH;;:==90K
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}