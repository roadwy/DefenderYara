
rule Trojan_BAT_Taskun_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 09 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a d2 9c 09 15 58 0d 09 16 fe 04 16 fe 01 13 07 11 07 2d ac 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Taskun_ARAQ_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 cc 00 00 5d 13 09 11 08 20 00 cc 00 00 5d 13 0a 07 11 09 91 13 0b 1f 16 8d 90 01 03 01 25 d0 90 01 01 00 00 04 28 90 01 03 0a 11 06 1f 16 5d 91 13 0c 07 11 0a 91 11 07 58 13 0d 11 0b 11 0c 61 13 0e 07 11 09 11 0e 11 0d 11 07 5d 59 d2 9c 00 11 06 17 58 13 06 11 06 20 00 cc 00 00 fe 04 13 0f 11 0f 2d 8b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}