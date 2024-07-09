
rule Trojan_BAT_RevengeRat_ATR_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {19 0b 02 0d 16 13 04 2b 2b 09 11 04 6f ?? ?? ?? 0a 13 05 08 11 05 28 ?? ?? ?? 0a 07 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 00 11 04 17 d6 13 04 11 04 09 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}