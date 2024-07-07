
rule Trojan_BAT_CrimsonRat_YNB_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.YNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 91 28 90 01 03 0a 0c 06 07 08 9d 00 07 17 58 0b 07 02 8e 69 fe 04 13 04 11 04 2d e1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}