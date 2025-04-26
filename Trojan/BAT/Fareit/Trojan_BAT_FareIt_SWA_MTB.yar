
rule Trojan_BAT_FareIt_SWA_MTB{
	meta:
		description = "Trojan:BAT/FareIt.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 0a 00 00 00 9f 00 00 00 72 00 00 00 d4 00 00 00 4e 00 00 00 d3 00 00 00 1d 01 00 00 44 00 00 00 8d 00 00 00 05 00 00 00 e9 00 00 00 38 9a 00 00 00 38 3a 00 00 00 20 03 00 00 00 28 ?? 00 00 06 3a ba ff ff ff } //2
		$a_03_1 = {fe 0c 03 00 45 01 00 00 00 21 00 00 00 38 1c 00 00 00 11 05 28 ?? 00 00 06 20 00 00 00 00 28 ?? 00 00 06 39 dc ff ff ff 26 38 d2 ff ff ff dc } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}