
rule Trojan_Win32_RedLine_CAR_MTB{
	meta:
		description = "Trojan:Win32/RedLine.CAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 99 b9 90 02 04 f7 f9 8b 45 08 0f be 0c 10 83 e1 90 01 01 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_RedLine_CAR_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.CAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 55 f8 8a 02 88 45 fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 10 0f b6 92 90 02 04 33 ca 88 4d ff 8b 45 08 03 45 f8 8a 08 88 4d fd 90 00 } //3
		$a_01_1 = {0f b6 4d fc 8b 55 08 03 55 f8 0f b6 02 2b c1 8b 4d 08 03 4d f8 88 01 e9 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}