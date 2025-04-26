
rule Trojan_MacOS_Amos_T_MTB{
	meta:
		description = "Trojan:MacOS/Amos.T!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 f6 c7 01 48 8d 85 31 ef ff ff 48 0f 44 d8 4d 85 e4 74 ?? 48 8d 75 b1 41 f6 c5 01 74 ?? 48 8b 75 c0 } //1
		$a_03_1 = {e8 3d 02 01 00 4d 8d 3c 04 49 83 ff f0 0f 83 4d 0d 00 00 49 89 c6 49 83 ff 16 77 ?? 0f 57 c0 0f 29 85 30 ef ff ff 48 c7 85 40 ef ff ff 00 00 00 00 45 00 ff 44 88 bd 30 ef ff ff 31 db } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}