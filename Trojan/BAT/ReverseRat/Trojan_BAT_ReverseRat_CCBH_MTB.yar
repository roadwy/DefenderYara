
rule Trojan_BAT_ReverseRat_CCBH_MTB{
	meta:
		description = "Trojan:BAT/ReverseRat.CCBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //1
		$a_01_1 = {41 45 53 5f 44 65 63 72 79 70 74 } //1 AES_Decrypt
		$a_01_2 = {58 4f 52 5f 44 65 63 72 79 70 74 } //1 XOR_Decrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}