
rule Trojan_Win32_TrojanDownloader_GI_MTB{
	meta:
		description = "Trojan:Win32/TrojanDownloader.GI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 81 e8 2f 86 2d d2 8b 3c 24 83 c4 04 81 c0 b6 ae 1b fa 29 c1 09 c9 57 81 e8 01 00 00 00 5e 81 c1 80 0b aa a5 49 56 29 c1 5a 81 e8 f9 05 74 8c 81 c0 bb 7f f5 05 81 c1 e9 ed 28 0a 81 c3 01 00 00 00 09 c9 b9 92 d8 32 eb b9 48 13 e4 2a 81 fb f1 c2 00 01 75 aa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}