
rule Trojan_BAT_Jalapeno_BAG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 20 fb 00 00 00 5d 58 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e5 } //2
		$a_01_1 = {08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 08 06 08 06 09 91 9c 06 09 11 08 9c 11 04 11 07 02 11 07 91 06 06 08 91 06 09 91 58 20 00 01 00 00 5d 91 61 d2 9c 11 07 17 58 13 07 11 07 02 8e 69 32 b3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Jalapeno_BAG_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 09 02 16 02 8e 69 6f ?? 00 00 0a 38 ?? 00 00 00 38 ?? 00 00 00 20 00 00 00 00 fe 0e 00 00 fe 0c 00 00 45 01 00 00 00 13 00 00 00 fe 0c 00 00 20 dc 03 00 00 3b e5 ff ff ff 38 00 00 00 00 11 01 6f ?? 00 00 0a 73 ?? 00 00 0a 13 03 38 ?? 00 00 00 11 09 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b 51 00 00 04 3a b6 ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 00 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}