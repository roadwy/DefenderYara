
rule Trojan_BAT_Kryptik_WR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.WR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {6e 17 6a d6 20 90 02 04 6a 5f b8 0c 09 11 05 08 84 95 d7 6e 20 90 02 04 6a 5f b8 0d 11 05 08 84 95 13 04 11 05 08 84 11 05 09 84 95 9e 11 05 09 84 11 04 90 00 } //10
		$a_03_1 = {9e 11 06 11 07 02 11 07 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 90 02 04 6a 5f b7 95 61 86 9c 11 07 17 d6 13 07 11 07 11 0a 31 9b 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_BAT_Kryptik_WR_MTB_2{
	meta:
		description = "Trojan:BAT/Kryptik.WR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {25 16 09 28 90 02 04 28 90 01 04 a2 28 90 01 09 13 04 11 04 28 90 01 09 07 6f 90 01 04 18 14 28 90 01 09 13 05 11 05 28 90 01 09 08 6f 90 01 04 17 18 8d 90 01 04 25 16 72 90 00 } //10
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_2 = {43 61 6c 6c 42 79 4e 61 6d 65 } //CallByName  1
		$a_80_3 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //GetObjectValue  1
		$a_80_4 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}