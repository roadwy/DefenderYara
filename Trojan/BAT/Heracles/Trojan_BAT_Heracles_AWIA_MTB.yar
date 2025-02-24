
rule Trojan_BAT_Heracles_AWIA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AWIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 2d 19 72 ?? ?? 00 70 28 ?? 00 00 0a 0b 16 2d 0b 72 ?? ?? 00 70 28 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 16 2d 06 2b 22 2b 23 2b 24 2b 29 2b 2a 1c 2d 2a 26 26 16 2d f4 2b 2a 2b 2b 06 16 06 8e 69 6f ?? 00 00 0a 13 04 de 37 09 2b db 07 2b da 6f ?? 00 00 0a 2b d5 09 2b d4 08 2b d3 6f ?? 00 00 0a 2b d1 09 2b d3 6f ?? 00 00 0a 2b ce } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}