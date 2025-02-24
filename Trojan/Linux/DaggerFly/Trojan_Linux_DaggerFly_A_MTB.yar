
rule Trojan_Linux_DaggerFly_A_MTB{
	meta:
		description = "Trojan:Linux/DaggerFly.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 41 52 4b 57 4f 4f 44 53 39 61 62 39 39 32 66 66 31 62 62 30 32 65 65 62 } //2 DARKWOODS9ab992ff1bb02eeb
		$a_01_1 = {69 6e 6a 65 63 74 5f 67 65 74 66 75 6e 63 20 25 73 20 4f 4b } //2 inject_getfunc %s OK
		$a_01_2 = {65 6c 66 70 61 73 74 65 5f 62 61 6b } //2 elfpaste_bak
		$a_01_3 = {6e 6f 20 73 65 6c 66 72 65 63 6f 76 65 72 21 } //1 no selfrecover!
		$a_01_4 = {74 6d 70 2f 73 75 6e 73 70 6e 65 73 } //1 tmp/sunspnes
		$a_03_5 = {48 81 c4 00 04 00 00 5b 41 5c c9 c3 55 48 89 e5 41 54 53 48 81 ec 00 04 00 00 48 89 fb 48 89 b5 f8 fb ff ff 48 89 95 f0 fb ff ff 48 ?? ?? ?? ?? ?? ?? b8 00 00 00 00 ba 7d 00 00 00 48 89 f7 48 89 d1 f3 48 ab 48 83 bd f0 fb ff ff 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2) >=8
 
}