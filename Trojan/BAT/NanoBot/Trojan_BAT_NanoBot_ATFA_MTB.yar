
rule Trojan_BAT_NanoBot_ATFA_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.ATFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {38 ba 00 00 00 2b 68 72 ?? 00 00 70 38 64 00 00 00 38 69 00 00 00 38 6e 00 00 00 72 ?? 00 00 70 38 6a 00 00 00 38 6f 00 00 00 16 2d 12 16 2d 0f 38 6e 00 00 00 6f ?? 00 00 0a 0b 14 0c 2b 1c } //3
		$a_03_1 = {07 08 16 08 8e 69 6f ?? 00 00 0a 0d de 44 06 38 ?? ff ff ff 28 ?? 00 00 0a 38 ?? ff ff ff 6f ?? 00 00 0a 38 ?? ff ff ff 06 38 ?? ff ff ff 28 ?? 00 00 0a 38 ?? ff ff ff 6f ?? 00 00 0a 38 ?? ff ff ff 06 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}