
rule Trojan_BAT_NjRat_ZZO_MTB{
	meta:
		description = "Trojan:BAT/NjRat.ZZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 6f ?? 00 00 0a 00 11 04 13 06 09 6f ?? 00 00 0a 13 07 11 07 11 06 20 ff ff ff ff 20 2f 01 00 00 20 d9 0b 00 00 fe 04 69 58 11 06 8e 69 6f ?? 00 00 0a 13 08 11 08 0a 2b 00 06 2a } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}