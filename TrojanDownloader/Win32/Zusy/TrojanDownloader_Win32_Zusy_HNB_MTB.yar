
rule TrojanDownloader_Win32_Zusy_HNB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zusy.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 2f 6e 65 77 2f 6e 65 74 5f 61 70 69 00 } //1 ⼀敮⽷敮彴灡i
		$a_01_1 = {00 7d 00 00 00 7d 00 66 69 6c 65 00 6e 61 6d 65 00 73 69 7a 65 00 64 6f 77 6e 6c 6f 61 64 5f 75 72 6c 00 } //1
		$a_01_2 = {00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00 5c 00 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}