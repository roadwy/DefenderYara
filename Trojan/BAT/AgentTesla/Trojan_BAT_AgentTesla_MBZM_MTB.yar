
rule Trojan_BAT_AgentTesla_MBZM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 11 90 01 01 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}