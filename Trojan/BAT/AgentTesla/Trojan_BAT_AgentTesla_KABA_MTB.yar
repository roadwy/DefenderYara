
rule Trojan_BAT_AgentTesla_KABA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 8e 69 5d 13 08 11 04 08 6f 90 01 01 00 00 0a 5d 13 09 07 11 08 91 13 0a 08 11 09 6f 90 01 01 00 00 0a 13 0b 02 07 11 04 28 90 01 01 00 00 06 13 0c 02 11 0a 11 0b 11 0c 28 90 01 01 00 00 06 13 0d 07 11 08 02 11 0d 28 90 01 01 00 00 06 9c 11 04 17 59 13 04 11 04 16 2f ad 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}