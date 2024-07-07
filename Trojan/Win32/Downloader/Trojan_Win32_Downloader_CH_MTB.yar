
rule Trojan_Win32_Downloader_CH_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 d2 8a 17 30 da 88 17 47 39 cf 75 f3 } //1
		$a_01_1 = {8a 07 90 47 90 2c e8 3c 01 77 f5 8b 07 90 8a 5f 04 86 c4 c1 c0 10 90 86 c4 29 f8 90 80 eb e8 01 f0 89 07 90 83 c7 05 90 88 d8 e2 db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}