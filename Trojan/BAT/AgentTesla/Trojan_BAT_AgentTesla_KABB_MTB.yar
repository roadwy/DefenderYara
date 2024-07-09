
rule Trojan_BAT_AgentTesla_KABB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 5d 91 08 09 08 6f ?? 01 00 0a 5d 6f ?? 01 00 0a 61 28 ?? 01 00 0a 07 09 17 58 07 8e 69 5d 91 28 ?? 01 00 0a 59 20 00 ?? 00 00 58 28 ?? 01 00 06 28 ?? 01 00 0a 9c 09 15 58 0d 09 16 2f b6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}