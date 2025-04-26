
rule Trojan_BAT_XWorm_DC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d d2 61 d2 52 08 11 04 06 11 04 91 11 04 1f 12 5a 20 00 01 00 00 5d 59 11 05 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}