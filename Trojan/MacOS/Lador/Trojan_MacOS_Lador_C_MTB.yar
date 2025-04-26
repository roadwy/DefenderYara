
rule Trojan_MacOS_Lador_C_MTB{
	meta:
		description = "Trojan:MacOS/Lador.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 89 fb e8 e2 e0 2e 00 48 89 03 8b 35 2b c7 4b 00 8b 3d 29 c7 4b 00 85 ff 75 25 48 83 ec 10 48 89 e7 e8 c9 e0 2e 00 8b 34 24 8b 7c 24 04 48 83 c4 10 89 35 04 c7 4b 00 89 f8 87 05 00 c7 4b 00 } //1
		$a_01_1 = {65 48 8b 0c 25 30 00 00 00 48 3b 61 10 76 43 48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 8b 44 24 30 48 89 04 24 48 8b 44 24 38 48 89 44 24 08 48 c7 44 24 10 0c 00 00 00 e8 82 d6 fa ff 48 8b 44 24 18 48 89 44 24 40 48 8b 6c 24 20 48 83 c4 28 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}