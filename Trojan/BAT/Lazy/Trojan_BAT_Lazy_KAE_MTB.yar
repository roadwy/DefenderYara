
rule Trojan_BAT_Lazy_KAE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 fe 0c 04 00 fe 0c 02 00 fe 0c 04 00 91 fe 0c 00 00 fe 0c 04 00 fe 0c 00 00 8e 69 5d 91 61 d2 9c fe 0c 04 00 7e 90 01 01 00 00 04 58 fe 0e 04 00 fe 0c 04 00 fe 0c 02 00 8e 69 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Lazy_KAE_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 93 28 90 01 01 00 00 0a 39 90 01 01 00 00 00 06 07 93 28 90 01 01 00 00 0a 3a 90 01 01 00 00 00 1f 41 38 90 01 01 00 00 00 1f 61 0c 06 07 06 07 93 08 59 1f 0d 58 1f 1a 5d 08 58 d1 9d 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}