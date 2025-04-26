
rule Trojan_BAT_SpyNoon_SCXM_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SCXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 13 0c 11 06 11 08 91 11 0c 61 13 0d 11 06 11 08 17 58 11 07 5d 91 13 0e } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}