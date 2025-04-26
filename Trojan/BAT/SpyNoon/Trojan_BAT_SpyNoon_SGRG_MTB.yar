
rule Trojan_BAT_SpyNoon_SGRG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SGRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 05 5d 05 58 05 5d 0a 03 06 91 0e 04 61 0e 05 59 20 00 02 00 00 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}