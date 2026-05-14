
rule Trojan_BAT_DcRat_ABD_MTB{
	meta:
		description = "Trojan:BAT/DcRat.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 09 06 09 91 08 09 08 8e 69 5d 91 61 d2 9c 08 09 08 8e 69 5d 08 09 08 8e 69 5d 91 17 58 20 00 01 00 00 5d d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d c8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}