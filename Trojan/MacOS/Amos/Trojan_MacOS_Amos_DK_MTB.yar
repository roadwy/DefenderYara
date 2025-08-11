
rule Trojan_MacOS_Amos_DK_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DK!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 1f 40 00 55 48 89 e5 53 50 e8 43 04 00 00 85 c0 75 07 48 83 c4 08 5b 5d c3 89 c7 89 c3 e8 e1 f9 ff ff 48 8d 35 9a 19 00 00 48 8d 15 29 1c 00 00 31 ff 48 89 c1 41 89 d8 31 c0 e8 d4 f5 ff ff } //1
		$a_01_1 = {89 c7 89 c3 e8 b1 fa ff ff 48 8d 35 6a 1a 00 00 48 8d 15 b8 1c 00 00 31 ff 48 89 c1 41 89 d8 31 c0 e8 a4 f6 ff ff 0f 1f 40 00 55 48 89 e5 53 50 e8 cd 04 00 00 a9 ef ff ff ff 75 0c 85 c0 0f 94 c0 48 83 c4 08 5b 5d c3 89 c7 89 c3 e8 69 fa ff ff 48 8d 35 22 1a 00 00 48 8d 15 8f 1c 00 00 31 ff 48 89 c1 41 89 d8 31 c0 e8 5c f6 ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}