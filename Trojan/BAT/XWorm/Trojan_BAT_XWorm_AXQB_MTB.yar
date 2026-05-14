
rule Trojan_BAT_XWorm_AXQB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AXQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 23 08 11 04 02 11 04 91 07 11 04 07 28 ?? ?? 00 06 25 26 69 5d 91 61 9c 11 04 1f 1c 28 ?? 00 00 06 d6 13 04 11 04 09 31 d8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}