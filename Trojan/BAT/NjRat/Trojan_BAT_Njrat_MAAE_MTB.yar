
rule Trojan_BAT_Njrat_MAAE_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MAAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 08 6f ?? 00 00 0a 00 11 04 04 6f ?? 00 00 0a 00 11 04 05 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 0a 06 02 16 02 8e b7 6f ?? 00 00 0a 0d 11 04 6f 4a 00 00 0a 00 09 13 05 2b 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}