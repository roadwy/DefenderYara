
rule Trojan_BAT_SpyNoon_GPAB_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.GPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 91 11 [0-18] 61 [0-18] 06 17 58 07 8e 69 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}