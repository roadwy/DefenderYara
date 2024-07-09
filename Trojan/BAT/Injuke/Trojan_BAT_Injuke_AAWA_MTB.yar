
rule Trojan_BAT_Injuke_AAWA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 00 28 ?? 06 00 06 11 00 28 ?? 06 00 06 28 ?? 06 00 06 13 04 20 02 00 00 00 38 ?? ff ff ff 11 00 20 4a dd b5 e4 28 ?? 06 00 06 28 ?? 06 00 06 6f ?? 04 00 0a 20 03 00 00 00 38 ?? ff ff ff 73 ?? 04 00 0a 13 0a 20 00 00 00 00 7e ?? 03 00 04 7b ?? 03 00 04 3a ?? ff ff ff 26 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}