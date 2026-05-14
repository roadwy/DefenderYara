
rule Trojan_BAT_Jalapeno_BAQ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 07 02 16 02 8e 69 ?? ?? 00 00 0a 20 06 00 00 00 7e 68 00 00 04 7b 40 00 00 04 3a 1d 00 00 00 26 20 00 00 00 00 38 12 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 09 00 fe 0c 09 00 45 01 00 00 00 13 00 00 00 fe 0c 09 00 20 dc 03 00 00 3b e5 ff ff ff 38 00 00 00 00 11 07 ?? ?? 00 00 0a 38 00 00 00 00 11 06 ?? ?? 00 00 0a 13 05 38 00 00 00 00 dd d4 fd ff ff } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}