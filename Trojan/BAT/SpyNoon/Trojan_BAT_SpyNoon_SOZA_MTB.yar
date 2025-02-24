
rule Trojan_BAT_SpyNoon_SOZA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SOZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 0c 08 19 32 4d 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0a 02 06 1f 10 63 20 ff 00 00 00 5f d2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}