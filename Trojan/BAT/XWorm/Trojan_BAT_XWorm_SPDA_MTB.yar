
rule Trojan_BAT_XWorm_SPDA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SPDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 58 d2 61 d2 52 09 17 58 0d 11 04 17 58 08 5d 13 04 09 06 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}