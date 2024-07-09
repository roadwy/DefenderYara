
rule Trojan_BAT_Heracles_SPZO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0b 11 09 16 73 ?? ?? ?? 0a 13 0c 11 0c 11 0a 6f ?? ?? ?? 0a 11 0a 6f ?? ?? ?? 0a 13 07 de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}