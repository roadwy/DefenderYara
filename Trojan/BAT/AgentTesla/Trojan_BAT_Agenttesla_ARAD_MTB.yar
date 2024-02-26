
rule Trojan_BAT_Agenttesla_ARAD_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 07 03 07 91 04 07 04 8e 69 5d 91 61 b4 9c 07 17 d6 0b 07 03 8e 69 32 e7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Agenttesla_ARAD_MTB_2{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 05 11 04 5d 13 08 11 05 1f 16 5d 13 09 11 05 17 58 11 04 5d 13 0a 07 11 08 91 08 11 09 91 61 13 0b 20 00 01 00 00 13 0c 11 0b 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 11 05 17 58 13 05 00 11 05 11 04 09 17 58 5a fe 04 13 0e 11 0e 2d a9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Agenttesla_ARAD_MTB_3{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 0d 06 17 58 13 0a 06 20 00 b6 00 00 5d 13 04 11 0a 20 00 b6 00 00 5d 13 0b 07 11 0b 91 09 58 13 0c 07 11 04 91 13 0d 11 06 06 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 04 11 0f 11 0c 59 09 5d d2 9c 06 17 58 0a 06 20 00 b6 00 00 fe 04 13 10 11 10 2d a6 } //00 00 
	condition:
		any of ($a_*)
 
}