
rule Trojan_MacOS_Dakkatoni_C_MTB{
	meta:
		description = "Trojan:MacOS/Dakkatoni.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6f 76 65 72 72 65 61 63 68 2e 62 61 64 6c 79 } //1 com.overreach.badly
		$a_02_1 = {74 65 6d 70 4f 62 90 02 04 2f 6f 75 74 70 75 74 2f 73 72 63 4f 62 66 73 2f 41 75 74 90 02 10 2f 61 67 65 6e 74 90 00 } //2
		$a_02_2 = {44 89 f8 c1 f8 1f c1 e8 1c 44 01 f8 83 e0 f0 44 89 f9 29 c1 48 63 c1 8a 44 05 c0 48 8b 4d a8 42 32 04 39 88 45 bf b9 90 01 01 00 00 00 48 8b 7d b0 48 89 de 48 8d 55 bf 4c 8b 25 42 48 01 00 41 ff d4 49 ff c7 4c 89 ef 4c 89 f6 41 ff d4 49 39 c7 72 af 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*2+(#a_02_2  & 1)*1) >=3
 
}