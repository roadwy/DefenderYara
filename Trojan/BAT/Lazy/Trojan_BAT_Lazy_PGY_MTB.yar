
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
rule Trojan_BAT_Lazy_PGY_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.PGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 6f 8f 00 00 06 13 06 06 6f 8f 00 00 06 13 07 11 06 8d 64 00 00 01 13 08 06 11 08 16 11 08 8e 69 6f b2 00 00 0a 26 11 08 73 3b 00 00 06 07 11 05 11 07 6f 3e 00 00 06 26 11 05 11 07 58 13 05 11 05 11 04 32 ba } //5
		$a_01_1 = {2b 51 7b 47 00 00 04 1f 0b 2e 23 2b 49 7b 4e 00 00 04 03 04 05 6f 51 00 00 06 0b 04 07 58 10 02 06 07 58 0a 05 07 59 10 03 05 2d 02 06 2a 02 28 3d 00 00 06 2d ca 02 7b 4e 00 00 04 6f 50 00 00 06 16 31 0a 02 7b 47 00 00 04 1f 0b 33 b2 06 2a } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}