
rule Trojan_BAT_Stealerc_AAHN_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AAHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 09 28 ?? ?? 00 06 11 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? fd ff ff 26 20 05 00 00 00 38 ?? fd ff ff 00 11 07 73 ?? 00 00 0a 13 03 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? 00 00 00 26 20 00 00 00 00 38 ?? 00 00 00 fe 0c 0c 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}