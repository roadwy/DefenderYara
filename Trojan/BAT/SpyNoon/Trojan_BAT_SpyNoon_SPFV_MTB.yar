
rule Trojan_BAT_SpyNoon_SPFV_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 08 17 58 11 05 5d 91 59 20 00 01 00 00 58 13 06 07 08 11 06 20 ff 00 00 00 5f 28 ?? ?? ?? 0a 9c 08 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}