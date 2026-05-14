
rule Trojan_Win64_StealC_MX_MTB{
	meta:
		description = "Trojan:Win64/StealC.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 05 35 e8 fa ff 31 c9 31 d2 45 31 c9 e8 2d e7 04 00 48 8d 74 24 68 48 89 f1 e8 2c 7c 02 00 48 8d 4c 24 50 48 89 f2 } //2
		$a_01_1 = {41 54 68 61 4f 41 55 6f 49 42 44 73 64 4e 53 37 37 69 6a 4e 37 51 46 4d 61 4e } //1 AThaOAUoIBDsdNS77ijN7QFMaN
		$a_01_2 = {69 00 6e 00 74 00 6e 00 6f 00 74 00 6d 00 67 00 72 00 73 00 76 00 63 00 } //1 intnotmgrsvc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}