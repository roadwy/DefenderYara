
rule Trojan_Win32_XWorm_PAYR_MTB{
	meta:
		description = "Trojan:Win32/XWorm.PAYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d8 3b d6 7f 2d 8b 4d e8 8b 59 0c 2b 59 14 8d 0c 13 8b 55 e4 8b 5a 0c 2b 5a 14 8b 55 dc 8a 14 13 30 11 ff 45 dc 39 45 dc 7e 03 89 7d dc ff 45 d8 eb cc } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}