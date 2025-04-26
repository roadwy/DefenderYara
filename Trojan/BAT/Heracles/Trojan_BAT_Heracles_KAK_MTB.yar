
rule Trojan_BAT_Heracles_KAK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 19 7e ?? 00 00 04 06 7e ?? 00 00 04 06 9a 1b 17 28 ?? 00 00 0a a2 06 17 58 0a 06 7e ?? 00 00 04 8e 69 32 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}