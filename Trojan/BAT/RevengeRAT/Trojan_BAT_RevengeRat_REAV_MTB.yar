
rule Trojan_BAT_RevengeRat_REAV_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.REAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 fe 01 13 07 11 07 2c 02 17 0d 03 09 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 02 11 06 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 07 08 d8 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 09 17 d6 0d 11 06 17 d6 13 06 11 06 11 05 31 b1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}