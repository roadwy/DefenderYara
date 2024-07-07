
rule Trojan_BAT_RedLineStealer_KAF_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 03 07 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 0c 06 72 90 01 02 00 70 08 28 90 01 02 00 0a 6f 90 01 02 00 0a 26 07 17 58 0b 07 02 6f 90 01 01 00 00 0a 3f 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}