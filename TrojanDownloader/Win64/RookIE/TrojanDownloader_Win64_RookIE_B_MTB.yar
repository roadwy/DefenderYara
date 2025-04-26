
rule TrojanDownloader_Win64_RookIE_B_MTB{
	meta:
		description = "TrojanDownloader:Win64/RookIE.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 6f 6f 6b 49 45 2f 31 2e 30 } //2 RookIE/1.0
		$a_01_1 = {73 36 34 2e 6a 70 67 } //2 s64.jpg
		$a_01_2 = {43 6f 6e 73 6f 6c 65 } //2 Console
		$a_01_3 = {6f 73 73 2d 63 6e 2d 68 61 6e 67 7a 68 6f 75 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d } //2 oss-cn-hangzhou.aliyuncs.com
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}