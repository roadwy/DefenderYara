
rule Trojan_BAT_AgentTesla_MBEK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 8e 69 5d 02 07 08 07 8e 69 5d 91 11 04 08 11 04 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 07 08 17 58 07 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 9c 08 15 58 0c 08 16 fe 04 16 fe 01 13 08 11 08 2d ab 90 00 } //1
		$a_01_1 = {51 4c 54 48 55 56 49 45 4e 2e 50 72 6f 70 65 72 74 69 65 73 } //1 QLTHUVIEN.Properties
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}