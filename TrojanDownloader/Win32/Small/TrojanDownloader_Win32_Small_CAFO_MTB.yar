
rule TrojanDownloader_Win32_Small_CAFO_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.CAFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 ab 66 ab bf 90 01 04 83 c9 ff 33 c0 c6 44 24 0c 90 01 01 f2 ae f7 d1 2b f9 c6 44 24 10 90 01 01 8b c1 8b f7 8b fa c6 44 24 14 90 01 01 c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 c6 44 24 15 00 f3 a4 8d 7c 24 0c 83 c9 ff f2 ae 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}