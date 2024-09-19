
rule Trojan_BAT_RustyStealer_BH_MTB{
	meta:
		description = "Trojan:BAT/RustyStealer.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 6f 76 00 00 0a 03 07 03 6f 74 00 00 0a 5d 6f 76 00 00 0a 61 d1 9d 00 07 17 58 0b 07 02 6f 74 00 00 0a fe 04 0c 08 2d d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}