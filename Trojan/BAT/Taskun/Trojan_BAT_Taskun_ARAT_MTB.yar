
rule Trojan_BAT_Taskun_ARAT_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 04 09 5d 13 08 07 11 08 91 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 11 04 1f 16 5d 91 61 13 09 11 09 07 11 04 17 58 09 5d 91 59 20 00 01 00 00 58 13 0a 07 11 08 11 0a 20 00 01 00 00 5d d2 9c 11 04 17 58 13 04 11 04 09 08 17 58 5a 32 af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_ARAT_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.ARAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 13 05 11 04 17 58 11 04 20 00 56 01 00 5d 13 06 20 00 56 01 00 5d 13 07 07 11 06 91 13 08 07 11 06 11 08 1f 16 8d 90 01 03 01 25 d0 90 01 01 00 00 04 28 90 01 03 0a 11 04 1f 16 5d 91 61 07 11 07 91 11 05 58 11 05 5d 59 d2 9c 11 04 17 58 13 04 11 04 20 00 56 01 00 32 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_ARAT_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.ARAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 20 00 01 00 00 13 06 11 05 17 58 13 07 11 05 20 00 1e 01 00 5d 13 08 11 07 20 00 1e 01 00 5d 13 09 06 11 08 91 13 0a 1f 16 8d 90 01 03 01 25 d0 90 01 01 00 00 04 28 90 01 03 0a 11 05 1f 16 5d 91 13 0b 06 11 09 91 11 06 58 13 0c 06 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 11 05 20 00 1e 01 00 fe 04 13 0d 11 0d 2d 8f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}