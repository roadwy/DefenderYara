
rule Trojan_BAT_FormBook_BAK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 06 07 11 06 9a 1f 10 ?? ?? 00 00 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dc } //2
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_3 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_BAK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 2c 11 2d 91 11 30 11 32 1a 5a 11 2f 5d 91 61 d2 13 33 11 2c 11 2d 17 58 91 11 30 11 32 1a 5a 17 58 11 2f 5d 91 61 d2 13 34 11 2c 11 2d 18 58 91 11 30 11 32 1a 5a 18 58 11 2f 5d 91 61 d2 13 35 11 2c 11 2d 19 58 91 11 30 11 32 1a 5a 19 58 11 2f 5d 91 61 d2 13 36 11 31 11 32 11 33 11 34 1e 62 60 11 35 1f 10 62 60 11 36 1f 18 62 60 9e 11 2d 1a 58 13 2d 11 32 17 58 13 32 11 32 11 2e 3f 7b ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}