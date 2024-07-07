
rule Trojan_BAT_Kryptik_YJ_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.YJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_03_0 = {04 08 04 6f 90 01 04 5d 17 d6 28 90 01 04 da 0d 06 09 28 90 02 0f 0a 00 08 17 d6 0c 08 11 04 13 05 11 05 31 c7 90 00 } //10
		$a_03_1 = {04 08 04 6f 90 01 04 5d 17 d6 28 90 01 04 da 0d 18 2b be 06 09 28 90 02 0f 0a 19 2b a9 08 17 d6 0c 08 11 04 13 05 11 05 31 c2 90 00 } //10
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
		$a_80_3 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  2
		$a_80_4 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //LateBinding  2
		$a_80_5 = {43 61 6c 6c 42 79 4e 61 6d 65 } //CallByName  2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=18
 
}