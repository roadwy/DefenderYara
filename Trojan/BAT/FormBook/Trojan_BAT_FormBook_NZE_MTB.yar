
rule Trojan_BAT_FormBook_NZE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {14 16 9a 26 16 2d f9 02 03 02 4b 04 03 05 66 60 61 58 0e 07 0e 04 e0 95 58 7e ?? 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 a7 00 00 06 58 54 2a } //3
		$a_81_1 = {30 66 31 37 32 61 37 62 2d 36 32 34 30 2d 34 37 35 35 2d 62 33 63 34 2d 37 64 61 37 31 61 32 38 36 39 66 36 } //1 0f172a7b-6240-4755-b3c4-7da71a2869f6
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_3 = {43 72 79 70 74 6f 43 6f 6e 66 69 67 } //1 CryptoConfig
		$a_81_4 = {44 65 63 72 79 70 74 } //1 Decrypt
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}