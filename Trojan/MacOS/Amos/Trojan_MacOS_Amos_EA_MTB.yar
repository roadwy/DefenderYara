
rule Trojan_MacOS_Amos_EA_MTB{
	meta:
		description = "Trojan:MacOS/Amos.EA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 83 00 91 e0 e3 00 91 9e fe ff 97 2b ff ff 97 f3 23 00 91 e8 23 00 91 e0 83 00 91 a1 23 01 d1 51 fe ff 97 e8 7f c0 39 e9 07 40 f9 1f 01 00 71 20 b1 93 9a 29 02 00 94 20 ff ff 97 e8 9f c1 39 e9 2b 40 f9 1f 01 00 71 e8 43 01 91 20 b1 88 9a 22 02 00 94 e8 7f c0 39 } //1
		$a_01_1 = {ff 83 01 d1 eb 2b 02 6d e9 23 03 6d f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 fc 02 00 94 f3 a3 90 52 73 3d aa 72 08 7c 33 9b 09 fd 7f d3 08 fd 65 93 08 01 09 0b 94 0c 80 52 08 81 14 1b 09 fd 42 1e f2 02 00 94 08 7c 33 9b 09 fd 7f d3 08 fd 65 93 08 01 09 0b 08 81 14 1b 00 01 62 1e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}