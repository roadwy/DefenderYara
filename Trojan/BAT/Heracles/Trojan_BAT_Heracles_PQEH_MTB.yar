
rule Trojan_BAT_Heracles_PQEH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PQEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 04 72 01 00 00 70 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 20 03 00 00 00 38 04 00 00 00 fe 0c 07 00 } //3
		$a_03_1 = {26 20 01 00 00 00 38 88 ff ff ff 11 04 6f ?? ?? ?? ?? 13 01 20 00 00 00 00 } //2
		$a_03_2 = {11 01 11 08 16 11 08 8e 69 6f ?? ?? ?? ?? 13 06 } //2
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}