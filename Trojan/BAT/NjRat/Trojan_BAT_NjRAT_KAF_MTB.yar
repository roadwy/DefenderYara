
rule Trojan_BAT_NjRAT_KAF_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 6f 90 01 01 00 00 0a 13 06 00 06 7b 90 01 01 00 00 04 11 06 6f 90 01 01 00 00 0a 13 07 11 07 15 fe 01 13 08 11 08 2c 1c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}