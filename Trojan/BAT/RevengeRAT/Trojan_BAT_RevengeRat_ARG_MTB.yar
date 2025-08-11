
rule Trojan_BAT_RevengeRat_ARG_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ARG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 0c 2b 30 02 08 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 0d 06 09 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 08 17 d6 0c 08 11 04 13 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}