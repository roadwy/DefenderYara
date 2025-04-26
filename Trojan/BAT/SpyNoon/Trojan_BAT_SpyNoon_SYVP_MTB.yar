
rule Trojan_BAT_SpyNoon_SYVP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SYVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 08 5d 08 58 08 5d 91 11 07 61 11 09 59 20 00 02 00 00 58 13 0a 16 13 1b 2b 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}