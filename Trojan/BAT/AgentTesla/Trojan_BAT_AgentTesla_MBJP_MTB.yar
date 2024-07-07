
rule Trojan_BAT_AgentTesla_MBJP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 15 5d 13 16 11 0a 11 18 5d 13 1c 11 0b 11 16 91 13 1d 11 14 11 1c 6f 90 01 01 00 00 0a 13 1e 02 11 0b 11 0a 28 90 01 01 00 00 06 13 1f 02 11 1d 11 1e 11 1f 28 90 01 01 00 00 06 13 20 11 0b 11 16 11 20 20 00 01 00 00 5d d2 9c 11 0a 17 59 13 0a 11 0a 16 fe 04 16 fe 01 13 21 11 21 2d a4 90 00 } //1
		$a_01_1 = {63 63 64 30 35 61 62 65 30 37 35 30 } //1 ccd05abe0750
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}