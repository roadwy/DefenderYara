
rule Trojan_BAT_Lazy_KAD_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 03 61 0a 7e ?? 00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 18 13 0e 2b 80 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}