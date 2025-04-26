
rule Trojan_Linux_VShell_A_MTB{
	meta:
		description = "Trojan:Linux/VShell.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 94 24 b0 00 00 00 48 8b 32 90 48 8b 42 08 48 8b 76 40 31 db 31 c9 31 ff ff d6 48 8b 94 24 b0 00 00 00 48 89 94 24 80 00 00 00 44 0f 11 bc 24 d8 00 00 00 c6 44 24 3f 00 48 8b 94 24 28 01 00 00 48 8b 32 ff d6 48 8b 9c 24 d8 00 00 00 48 8b 84 24 80 00 00 00 48 8b 8c 24 e0 00 00 00 48 8b ac 24 30 01 00 00 48 81 c4 38 01 00 00 } //1
		$a_01_1 = {48 8b 4a 10 48 8b 72 18 48 89 74 24 48 48 8b 52 08 48 89 54 24 50 48 8b 19 48 8b 49 08 48 89 4c 24 40 48 8d 05 e3 e0 05 00 0f 1f 00 e8 db e7 c2 ff 48 8b 5c 24 50 48 89 c1 48 8b 7c 24 40 31 f6 45 31 c0 4d 89 c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}