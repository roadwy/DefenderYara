
rule Trojan_BAT_RevengeRat_WZI_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.WZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 7e 18 00 00 0a 0b 06 6f ?? ?? ?? 0a 17 59 13 06 2b 20 00 07 06 11 06 6f ?? ?? ?? 0a 13 07 12 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 11 06 17 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}