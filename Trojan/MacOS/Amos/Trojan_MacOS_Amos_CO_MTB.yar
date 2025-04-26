
rule Trojan_MacOS_Amos_CO_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CO!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff c3 03 d1 fc 6f 09 a9 fa 67 0a a9 f8 5f 0b a9 f6 57 0c a9 f4 4f 0d a9 fd 7b 0e a9 fd 83 03 91 f6 03 02 aa f3 03 01 aa f4 03 00 aa 83 01 00 34 e0 03 14 aa e1 03 13 aa e2 03 16 aa fd 7b 4e a9 f4 4f 4d a9 f6 57 4c a9 f8 5f 4b a9 fa 67 4a a9 fc 6f 49 a9 ff c3 03 91 } //1
		$a_01_1 = {ff c3 01 d1 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f3 03 08 aa 1f 7d 00 a9 1f 09 00 f9 08 5c 40 39 09 1d 00 13 0a 2c 40 a9 3f 01 00 71 59 b1 80 9a 7a b1 88 9a fa 2e 00 b4 15 00 80 52 fc 37 00 91 58 01 00 f0 18 e3 09 91 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}