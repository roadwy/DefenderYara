
rule Trojan_BAT_SpyNoon_SFRG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SFRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 5d 08 58 13 19 11 19 08 5d 13 1a 07 11 1a 91 13 1b 11 1b 11 12 61 13 1c 11 1c 20 00 04 00 00 58 13 1d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}