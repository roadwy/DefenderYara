
rule Trojan_BAT_Heracles_KAAC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 1e 5a 1e 6f ?? 00 00 0a 0d 09 18 28 ?? 00 00 0a 13 04 07 08 11 04 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 08 17 58 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}