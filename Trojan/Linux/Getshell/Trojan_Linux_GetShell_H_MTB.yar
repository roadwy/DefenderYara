
rule Trojan_Linux_GetShell_H_MTB{
	meta:
		description = "Trojan:Linux/GetShell.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 1e fa 31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 45 31 c0 31 c9 48 8d 3d 01 ff ff ff ff 15 b3 2d 00 00 f4 } //1
		$a_01_1 = {80 3d 65 2d 00 00 00 75 2b 55 48 83 3d 42 2d 00 00 00 48 89 e5 74 0c 48 8b 3d 46 2d 00 00 e8 d9 fd ff ff } //1
		$a_01_2 = {31 f6 89 df e8 3a ff ff ff be 01 00 00 00 89 df e8 2e ff ff ff be 02 00 00 00 89 df e8 22 ff ff ff 48 8d 3d 6b 10 00 00 31 c0 31 d2 48 8d 74 24 08 48 89 7c 24 08 48 89 44 24 10 e8 13 ff ff ff 48 8d 3d 56 10 00 00 e8 d7 fe ff ff 48 8b 44 24 28 64 48 2b 04 25 28 00 00 00 } //1
		$a_01_3 = {f3 0f 1e fa 41 55 31 ff 41 54 55 53 48 81 ec e8 00 00 00 64 48 8b 04 25 28 00 00 00 48 89 84 24 d8 00 00 00 31 c0 e8 a5 ff ff ff 48 89 05 ce 2e 00 00 48 85 c0 74 6d 48 89 c7 48 8d 5c 24 08 4c 8d 6c 24 10 e8 57 ff ff ff 89 05 a9 2e 00 00 41 89 c4 e8 39 ff ff ff 48 89 c5 66 0f 1f 44 00 00 } //-2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*-2) >=2
 
}