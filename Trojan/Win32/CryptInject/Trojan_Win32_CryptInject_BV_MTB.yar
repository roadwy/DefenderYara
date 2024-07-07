
rule Trojan_Win32_CryptInject_BV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 45 d8 29 45 e8 e9 90 01 01 ff ff ff 8b 4d 08 8b 55 d0 89 11 8b 45 08 8b 4d f4 89 48 04 8b e5 5d c2 08 00 90 00 } //1
		$a_01_1 = {8b 5d 08 8d 5c 9d e0 8b 33 8b ce 23 cf 89 4d f0 8b ca d3 ee 8b 4d fc 0b 75 f4 89 33 8b 75 f0 d3 e6 ff 45 08 83 7d 08 03 89 75 f4 7c d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}