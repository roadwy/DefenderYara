
rule Trojan_BAT_XWorm_AIAB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AIAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff ff ff 11 08 75 02 00 00 1b 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}