
rule Trojan_BAT_Bladabindi_GPPA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GPPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7a 06 14 6f ?? 00 00 0a 75 ?? 00 00 01 0b 07 14 28 ?? 00 00 0a 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}