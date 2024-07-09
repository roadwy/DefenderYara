
rule Trojan_BAT_Heracles_AMMF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 07 09 16 6f ?? 00 00 0a 13 ?? 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}