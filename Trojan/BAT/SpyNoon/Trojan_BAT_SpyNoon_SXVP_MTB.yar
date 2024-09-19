
rule Trojan_BAT_SpyNoon_SXVP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SXVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 91 11 07 61 11 09 59 20 00 02 00 00 58 13 0a 16 13 1b 2b 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}