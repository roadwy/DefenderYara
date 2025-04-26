
rule Ransom_Linux_Babuk_AB_MTB{
	meta:
		description = "Ransom:Linux/Babuk.AB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 00 00 f0 00 60 08 91 01 00 40 f9 00 00 00 b0 03 a0 09 91 00 00 00 b0 02 e0 03 91 e0 17 40 f9 13 fe ff 97 80 00 00 f0 00 60 08 91 01 00 40 f9 00 00 00 b0 03 c0 09 91 00 00 00 b0 02 c0 05 91 e0 17 40 f9 0a fe ff 97 e0 1f 40 b9 1f 00 00 71 61 00 00 54 e0 17 40 f9 c1 e7 ff 97 } //1
		$a_01_1 = {e0 3f 40 b9 1f 00 13 6b 22 fd ff 54 e1 27 40 f9 e0 03 15 2a 23 00 00 8b e0 03 14 2a e1 23 40 f9 20 00 00 8b e2 3f 40 b9 e1 03 00 aa e0 03 03 aa 91 fd ff 97 1f 20 03 d5 f3 53 41 a9 f5 13 40 f9 fd 7b c5 a8 c0 03 5f d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}