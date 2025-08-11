
rule Trojan_Linux_SAgnt_Y_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.Y!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {e0 03 00 90 00 e8 47 f9 26 94 01 94 e0 03 00 90 00 e8 47 f9 e1 a3 01 91 32 94 01 94 c0 fc ff 35 e0 37 40 f9 20 05 00 b4 03 03 00 91 60 60 40 39 } //1
		$a_01_1 = {fd 7b b9 a9 fd 03 00 91 f3 53 01 a9 f7 63 03 a9 f8 03 00 b0 13 03 00 91 f7 03 00 2a f5 5b 02 a9 f6 03 02 aa 60 12 40 b9 f5 03 01 aa a1 a7 01 94 e1 03 00 2a 60 06 40 b9 61 12 00 b9 9d a7 01 94 } //1
		$a_01_2 = {fd 7b be a9 fd 03 00 91 f3 0b 00 f9 f3 03 00 b0 60 c2 4e 39 40 01 00 37 de ff ff 97 e0 03 00 90 00 c8 47 f9 80 00 00 b4 c0 03 00 f0 00 c0 1d 91 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}