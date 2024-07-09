
rule Trojan_BAT_Vidar_AATR_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 16 6f ?? 01 00 0a 13 07 12 07 28 ?? 01 00 0a 13 05 11 04 11 05 6f ?? 00 00 0a 06 17 58 0a 06 09 6f ?? 01 00 0a 32 d7 11 04 6f ?? 01 00 0a 13 06 de 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}