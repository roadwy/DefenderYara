
rule Trojan_BAT_AgentTesla_KAAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 11 08 07 8e 69 5d 07 11 08 07 8e 69 5d 91 08 11 08 08 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 07 11 08 17 58 07 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 90 01 02 00 00 58 20 90 01 02 00 00 5d 28 90 01 01 00 00 0a 9c 00 11 08 15 58 13 08 11 08 16 fe 04 16 fe 01 13 09 11 09 2d a4 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}