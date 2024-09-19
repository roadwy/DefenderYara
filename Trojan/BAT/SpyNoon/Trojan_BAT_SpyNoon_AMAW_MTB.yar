
rule Trojan_BAT_SpyNoon_AMAW_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 95 d2 13 [0-0a] 61 [0-0f] 20 ff 00 00 00 5f d2 9c 11 ?? 17 6a 58 13 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}