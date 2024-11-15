
rule Trojan_BAT_Agenttesla_PPMH_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PPMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}