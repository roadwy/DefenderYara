
rule Trojan_BAT_Jalapeno_ARR_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f d1 0b 07 08 61 06 11 05 1f 0f 5f 93 61 d1 0b 06 07 1f 0f 5f 93 0c 07 1a 63 } //8
		$a_01_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //2 RijndaelManaged
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2) >=10
 
}
rule Trojan_BAT_Jalapeno_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 08 09 6f ?? ?? ?? ?? 00 07 8e 69 09 8e 69 58 8d ?? ?? ?? ?? 13 04 07 16 11 04 16 07 8e 69 } //12
		$a_01_1 = {09 16 11 04 07 8e 69 09 8e 69 28 } //8
	condition:
		((#a_03_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}
rule Trojan_BAT_Jalapeno_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Jalapeno.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_81_0 = {24 63 37 39 61 66 31 63 39 2d 32 33 39 63 2d 34 37 64 34 2d 62 33 33 66 2d 35 35 32 65 63 30 64 62 33 63 36 35 } //8 $c79af1c9-239c-47d4-b33f-552ec0db3c65
		$a_81_1 = {52 75 6e 6e 65 72 5f 41 2e 4d 79 } //12 Runner_A.My
	condition:
		((#a_81_0  & 1)*8+(#a_81_1  & 1)*12) >=20
 
}