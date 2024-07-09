
rule Trojan_BAT_AgentTesla_AAKM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 5d 07 11 07 07 8e 69 5d 91 08 11 07 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 11 07 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 00 11 07 15 58 13 07 11 07 16 fe 04 16 fe 01 13 08 11 08 2d a4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}