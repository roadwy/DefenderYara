
rule Trojan_BAT_AgentTesla_MBDE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 08 09 11 08 9a 1f 10 28 90 01 01 00 00 0a 9c 11 08 17 58 13 08 11 08 09 8e 69 fe 04 13 09 11 09 2d dd 90 00 } //1
		$a_01_1 = {5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d 5a 5a 2d } //1 ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-ZZ-
		$a_01_2 = {01 25 16 1f 2d 9d 6f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}