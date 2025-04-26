
rule Trojan_BAT_SpyNoon_SPCP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 13 09 07 11 04 11 09 07 11 07 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}