
rule Trojan_BAT_XWorm_FPP_MTB{
	meta:
		description = "Trojan:BAT/XWorm.FPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 01 13 05 11 05 2c 12 07 11 04 06 11 04 91 20 c5 00 00 00 61 b4 9c 00 2b 0a 00 07 11 04 06 11 04 91 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}