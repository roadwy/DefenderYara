
rule Trojan_BAT_Heracles_AIVA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AIVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 32 2b 34 16 2b 34 8e 69 2b 33 2b 38 2b 3a 2b 3f 2b 41 2b 46 11 06 72 ?? ?? 00 70 03 28 ?? ?? 00 06 05 72 ?? ?? 00 70 6f ?? 00 00 0a 17 0b dd ?? 00 00 00 11 05 2b ca 06 2b c9 06 2b c9 6f ?? 00 00 0a 2b c6 11 05 2b c4 6f ?? 00 00 0a 2b bf 11 04 2b bd 6f ?? 00 00 0a 2b b8 13 06 2b b6 } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}