
rule Trojan_BAT_AgentTesla_MBFO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 03 08 1a 58 19 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}