
rule TrojanDownloader_Win32_Thamcower_A{
	meta:
		description = "TrojanDownloader:Win32/Thamcower.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 00 61 00 69 00 78 00 61 00 6e 00 64 00 6f 00 34 00 6c 00 69 00 6e 00 6b 00 } //1 baixando4link
		$a_01_1 = {76 00 6d 00 6d 00 72 00 65 00 67 00 31 00 36 00 2e 00 64 00 6c 00 6c 00 00 00 } //1
		$a_01_2 = {52 6f 74 61 43 6f 6d 61 6e 64 6f 00 } //1 潒慴潃慭摮o
		$a_01_3 = {4d 61 78 69 6d 75 73 32 30 31 30 00 } //1
		$a_01_4 = {70 69 6f 6e 65 65 72 00 } //1 楰湯敥r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}