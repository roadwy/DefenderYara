
rule Trojan_BAT_Spynoon_ALEA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ALEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0d 03 09 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 03 09 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 11 05 } //3
		$a_03_1 = {03 19 8d d9 00 00 01 25 16 12 00 28 ?? 00 00 0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 28 ?? 00 00 2b 6f ?? 00 00 0a 00 00 11 05 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}