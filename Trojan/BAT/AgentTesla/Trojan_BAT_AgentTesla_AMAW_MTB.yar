
rule Trojan_BAT_AgentTesla_AMAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 11 01 8e 69 5d 02 11 01 11 03 11 01 8e 69 5d 91 11 02 11 03 11 02 6f 90 01 01 01 00 0a 5d 6f 90 01 01 01 00 0a 61 28 90 01 01 02 00 06 11 01 11 03 17 58 11 01 8e 69 5d 91 28 90 01 01 02 00 06 59 20 00 01 00 00 58 28 90 01 01 02 00 06 28 90 01 01 02 00 06 9c 38 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}