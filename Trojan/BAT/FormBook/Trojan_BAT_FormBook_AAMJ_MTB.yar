
rule Trojan_BAT_FormBook_AAMJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 8c 04 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 02 28 90 01 01 00 00 06 2a 90 00 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {6a 00 41 00 34 00 56 00 32 00 77 00 61 00 4b 00 56 00 47 00 2b 00 38 00 4a 00 67 00 6b 00 64 00 42 00 62 00 72 00 43 00 65 00 70 00 71 00 7a 00 42 00 39 00 37 00 2f 00 74 00 2f 00 36 00 38 00 78 00 6f 00 56 00 4c 00 2b 00 69 00 55 00 31 00 66 00 73 00 67 00 3d 00 } //1 jA4V2waKVG+8JgkdBbrCepqzB97/t/68xoVL+iU1fsg=
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}