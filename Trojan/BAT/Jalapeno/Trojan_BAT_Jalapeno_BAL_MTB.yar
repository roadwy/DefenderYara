
rule Trojan_BAT_Jalapeno_BAL_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 0d 11 11 6f 0c 00 00 0a 17 73 0d 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 ?? ?? 00 00 0a 38 5b 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0c 00 fe 0c 0c 00 45 01 00 00 00 4c 00 00 00 fe 0c 0c 00 20 dc 03 00 00 3b e5 ff ff ff 38 39 00 00 00 11 0d ?? ?? 00 00 0a 73 10 00 00 0a 13 03 20 02 00 00 00 7e 62 00 00 04 7b 6b 00 00 04 39 c2 ff ff ff 26 20 00 00 00 00 38 b7 ff ff ff 11 02 ?? ?? 00 00 0a 38 c7 ff ff ff } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}