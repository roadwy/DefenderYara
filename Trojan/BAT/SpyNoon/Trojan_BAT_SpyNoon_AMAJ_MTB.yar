
rule Trojan_BAT_SpyNoon_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 ?? 07 06 91 11 ?? 61 13 ?? 07 06 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_SpyNoon_AMAJ_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 17 58 20 ff 00 00 00 5f 0d 11 ?? 11 ?? 09 95 58 20 ff 00 00 00 5f } //2
		$a_03_1 = {95 58 d2 13 [0-1e] 20 ff 00 00 00 5f d2 13 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}