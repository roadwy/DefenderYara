
rule Trojan_Linux_KiteShield_B_MTB{
	meta:
		description = "Trojan:Linux/KiteShield.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 ed 48 89 e7 e8 66 00 00 00 50 31 d2 31 c0 31 c9 31 f6 31 ff 31 ed 45 31 c0 45 31 c9 45 31 d2 45 31 db 45 31 e4 45 31 ed 45 31 f6 45 31 ff 5b } //1
		$a_01_1 = {49 8b 44 24 10 31 ff 49 8b 4c 24 20 41 b8 ff ff ff ff 4d 8b 54 24 08 ba 02 00 00 00 45 8b 74 24 04 48 89 c6 48 89 4c 24 18 b9 22 00 00 00 81 e6 ff 0f 00 00 49 03 74 24 28 4c 89 54 24 28 66 41 83 7f 10 03 48 89 74 24 20 40 0f 94 c7 48 25 00 f0 ff ff 45 31 c9 48 c1 e7 23 48 01 c7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}