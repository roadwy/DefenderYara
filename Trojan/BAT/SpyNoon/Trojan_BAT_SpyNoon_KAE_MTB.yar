
rule Trojan_BAT_SpyNoon_KAE_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 93 1a 5b d1 9d 07 17 58 0b 07 06 8e 69 32 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}