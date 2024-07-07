
rule Trojan_Win32_RedLine_RDS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4d cc 8d 45 e4 89 7d f4 89 55 e4 e8 90 01 04 8b 45 e4 33 c7 31 45 e0 89 35 90 01 04 8b 45 e0 29 45 fc 81 45 e8 90 01 04 ff 4d dc 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLine_RDS_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 a3 90 01 04 a1 90 01 04 33 d2 b9 00 01 00 00 f7 f1 89 15 90 01 04 a1 90 01 04 0f b6 80 90 01 04 03 05 90 01 04 33 d2 b9 00 01 00 00 f7 f1 90 00 } //2
		$a_03_1 = {49 81 c9 00 ff ff ff 41 8a 89 90 01 04 88 4d fb 0f b6 45 fb 8b 0d 90 01 04 03 8d d0 fc ff ff 0f be 11 33 d0 a1 90 01 04 03 85 d0 fc ff ff 88 10 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}