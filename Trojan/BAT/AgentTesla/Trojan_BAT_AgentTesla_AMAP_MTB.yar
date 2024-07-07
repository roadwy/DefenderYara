
rule Trojan_BAT_AgentTesla_AMAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 07 8e 69 5d 13 07 11 06 08 6f 90 01 01 00 00 0a 5d 13 08 07 11 07 91 13 09 08 11 08 6f 90 01 01 00 00 0a 13 0a 02 07 11 06 28 90 01 01 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 90 01 01 00 00 06 13 0c 07 11 07 11 0c 20 00 01 00 00 5d d2 9c 11 06 17 59 13 06 11 06 16 2f ac 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}