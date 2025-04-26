
rule Trojan_BAT_RedLine_RPY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 1e 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedLine_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 87 00 00 0a 03 08 1f 09 58 1e 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedLine_RPY_MTB_3{
	meta:
		description = "Trojan:BAT/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 13 0f 38 6b ff ff ff 06 6f d2 00 00 0a 0b 19 13 0f 38 5c ff ff ff 11 08 2c 19 1b 13 0f 38 50 ff ff ff 16 13 08 1d 13 0f 38 45 ff ff ff 11 08 17 58 13 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedLine_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 02 06 91 66 d2 9c 02 06 8f 18 00 00 01 25 71 18 00 00 01 20 83 00 00 00 59 d2 81 18 00 00 01 02 06 8f 18 00 00 01 25 71 18 00 00 01 1f 25 58 d2 81 18 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d b9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}