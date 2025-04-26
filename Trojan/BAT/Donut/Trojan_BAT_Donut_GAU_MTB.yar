
rule Trojan_BAT_Donut_GAU_MTB{
	meta:
		description = "Trojan:BAT/Donut.GAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1d 00 06 07 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 58 0c 08 07 6f ?? 00 00 0a fe 04 13 04 11 04 2d d4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}