
rule Trojan_BAT_Phoenixrat_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Phoenixrat.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 0b 07 6f ?? 00 00 0a 17 da 0c 16 0d 2b 20 7e ?? 00 00 04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 dc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}