
rule Trojan_BAT_Taskun_ARAC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 08 11 07 17 58 13 09 11 07 20 00 b6 00 00 5d 13 0a 11 09 20 00 b6 00 00 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 11 08 5d d2 9c 00 11 07 17 58 13 07 11 07 20 00 b6 00 00 fe 04 13 10 11 10 2d 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Taskun_ARAC_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 08 6f 53 00 00 0a 5d 13 06 11 05 08 6f 53 00 00 0a 5b 13 07 08 72 36 01 00 70 18 18 8d 90 01 03 01 25 16 11 06 8c 90 01 03 01 a2 25 17 11 07 8c 90 01 03 01 a2 28 90 01 03 0a a5 19 00 00 01 13 08 12 08 28 55 00 00 0a 13 09 07 11 09 6f 90 01 03 0a 00 00 11 05 17 58 13 05 11 05 08 6f 53 00 00 0a 08 6f 57 00 00 0a 5a fe 04 13 0a 11 0a 2d 8c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}