
rule Trojan_Win32_RedLine_BQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 75 dc 8b 5d d4 8b 7d d0 83 e7 03 8a 87 90 02 04 30 04 33 46 eb 90 00 } //1
		$a_01_1 = {6c 6f 67 67 69 6e 67 2e 62 69 6e } //1 logging.bin
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_RedLine_BQ_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 b4 8b 45 bc 33 d2 f7 75 b4 8b 4d 10 0f b6 14 11 0f b6 45 c3 33 c2 88 45 eb 8b 4d 08 03 4d bc 8a 55 eb 88 11 eb } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}