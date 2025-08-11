
rule Trojan_BAT_Lazy_PGY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 00 20 00 0b fc ff 1d 63 66 20 00 f6 ff ff 18 63 65 1d 63 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Lazy_PGY_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.PGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 00 41 00 39 00 42 00 31 00 75 00 4b 00 46 00 64 00 64 00 51 00 64 00 71 00 69 00 4c 00 53 00 53 00 75 00 7a 00 76 00 44 00 32 00 47 00 68 00 4c 00 31 00 6f 00 32 00 4a 00 76 00 2b 00 76 00 } //5 iA9B1uKFddQdqiLSSuzvD2GhL1o2Jv+v
	condition:
		((#a_01_0  & 1)*5) >=5
 
}