
rule Trojan_BAT_Crysan_BAC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 01 20 00 00 00 00 7e 5a 00 00 04 7b 56 00 00 04 3a c3 ff ff ff 26 20 00 00 00 00 38 b8 ff ff ff 11 09 72 01 00 00 70 ?? ?? 00 00 0a ?? ?? 00 00 0a 20 01 00 00 00 7e 5a 00 00 04 7b 0e 00 00 04 39 93 ff ff ff 26 20 01 00 00 00 38 88 ff ff ff 11 09 72 5b 00 00 70 ?? ?? 00 00 0a ?? ?? 00 00 0a 38 84 ff ff ff 73 09 00 00 0a 13 0c 38 00 00 00 00 00 20 30 a5 04 00 8d 07 00 00 01 25 d0 06 00 00 04 } //2
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}