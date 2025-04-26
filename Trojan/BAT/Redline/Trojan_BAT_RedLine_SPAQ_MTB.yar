
rule Trojan_BAT_RedLine_SPAQ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.SPAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 03 16 03 8e 69 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 00 02 28 ?? ?? ?? 0a 26 17 0d de 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}