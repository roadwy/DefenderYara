
rule Trojan_BAT_AgentTesla_KA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 17 58 17 59 7e 90 01 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 04 03 08 19 58 18 59 03 8e 69 5d 91 59 20 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}