
rule Trojan_BAT_Stealer_AAAF_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AAAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 13 00 06 07 02 03 07 91 07 28 ?? 00 00 06 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0c 08 2d e3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}