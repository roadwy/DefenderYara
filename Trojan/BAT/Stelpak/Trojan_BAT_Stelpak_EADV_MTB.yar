
rule Trojan_BAT_Stelpak_EADV_MTB{
	meta:
		description = "Trojan:BAT/Stelpak.EADV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 08 28 1f 00 00 0a 9c 07 08 04 08 05 5d 91 9c 08 17 58 0c 08 20 00 01 00 00 3f e0 ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Stelpak_EADV_MTB_2{
	meta:
		description = "Trojan:BAT/Stelpak.EADV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 07 1f 28 5a 58 13 08 28 2f 00 00 0a 07 11 08 1e 6f 30 00 00 0a 17 8d 30 00 00 01 6f 31 00 00 0a 28 08 00 00 06 72 00 01 00 70 28 32 00 00 0a 39 41 00 00 00 07 11 08 1f 14 58 28 2e 00 00 0a 13 09 07 11 08 1f 10 58 28 2e 00 00 0a 13 0a 11 0a 8d 1d 00 00 01 80 05 00 00 04 07 11 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}