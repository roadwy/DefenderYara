
rule Trojan_BAT_Taskun_ARAS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 05 11 04 5d 13 09 07 11 09 91 08 11 05 1f 16 5d 91 61 13 0a 11 0a 07 11 05 17 58 11 04 5d 91 59 20 00 01 00 00 58 13 0b 07 11 09 11 0b 20 00 01 00 00 5d d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0c 11 0c 2d b2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_ARAS_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 08 8e 69 5d 08 11 04 08 8e 69 5d 91 09 11 04 09 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 28 90 01 03 0a 08 11 04 17 58 08 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 11 04 15 58 13 04 00 11 04 16 fe 04 16 fe 01 13 08 11 08 2d a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_ARAS_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0d 06 17 58 13 09 06 20 00 cc 00 00 5d 13 04 11 09 20 00 cc 00 00 5d 13 0a 07 11 04 91 13 0b 1f 16 8d 90 01 03 01 25 d0 90 01 01 00 00 04 28 90 01 03 0a 06 1f 16 5d 91 13 0c 07 11 0a 91 09 58 13 0d 11 0b 11 0c 61 13 0e 07 11 04 11 0e 11 0d 09 5d 59 d2 9c 06 17 58 0a 06 20 00 cc 00 00 fe 04 13 0f 11 0f 2d 96 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}