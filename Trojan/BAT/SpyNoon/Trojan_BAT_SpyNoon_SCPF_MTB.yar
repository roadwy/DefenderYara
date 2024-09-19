
rule Trojan_BAT_SpyNoon_SCPF_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SCPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 10 11 0e 11 10 61 13 11 11 07 11 08 d4 11 11 20 ff 00 00 00 5f 28 30 00 00 0a 9c 11 08 17 6a 58 13 08 } //5
		$a_01_1 = {5d d4 91 13 0d 11 04 11 0d 58 11 06 09 95 58 20 ff 00 00 00 5f 13 04 11 06 09 95 13 05 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}