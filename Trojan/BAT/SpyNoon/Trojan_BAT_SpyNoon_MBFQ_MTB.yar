
rule Trojan_BAT_SpyNoon_MBFQ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 24 00 24 00 33 00 24 00 24 00 24 00 30 00 34 00 24 00 24 00 24 00 46 00 46 00 46 00 46 00 24 00 24 00 42 00 38 00 24 00 24 00 24 00 24 } //1
		$a_01_1 = {24 00 24 00 30 00 38 00 24 00 24 00 24 00 24 00 45 00 31 00 46 00 42 00 41 00 30 00 45 00 24 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 30 00 31 00 34 00 43 00 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}