
rule Trojan_MacOS_Amos_DA_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 8c 24 98 00 00 00 48 8b 44 cc 20 48 89 44 24 18 e8 f4 44 03 00 e8 ef 46 03 00 48 8b 44 24 18 e8 c5 47 03 00 0f 1f 44 00 00 e8 3b 45 03 00 48 8b 8c 24 98 00 00 00 48 ff c1 48 8b 84 24 00 01 00 00 } //1
		$a_01_1 = {48 89 44 24 68 48 89 4c 24 28 66 90 e8 db 07 03 00 48 8d 05 0b a8 8b 00 bb 21 00 00 00 e8 2a 0d 03 00 48 8b 44 24 68 48 8b 5c 24 28 e8 1b 0d 03 00 48 8d 05 4a ca 8a 00 bb 02 00 00 00 e8 0a 0d 03 00 e8 05 08 03 00 48 8b 74 24 70 4c 8b 44 24 50 e9 b8 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}