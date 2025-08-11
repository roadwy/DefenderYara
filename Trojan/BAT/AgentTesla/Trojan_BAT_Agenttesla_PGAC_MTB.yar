
rule Trojan_BAT_Agenttesla_PGAC_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PGAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 16 fe 02 13 04 11 04 2c 13 02 7b ?? 00 00 04 12 01 28 ?? 00 00 0a 6f ?? ?? 00 0a 00 08 17 59 25 0c 16 fe 02 13 05 11 05 2c 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}