
rule Trojan_MacOS_Lador_D_MTB{
	meta:
		description = "Trojan:MacOS/Lador.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 89 fb e8 64 70 38 00 48 89 03 8b 35 fb d7 57 00 8b 3d f9 d7 57 00 85 ff 75 25 48 83 ec 10 48 89 e7 e8 4b 70 38 00 8b 34 24 8b 7c 24 04 48 83 c4 10 89 35 d4 d7 57 00 89 f8 87 05 d0 d7 57 00 89 73 08 89 7b 0c 48 89 ec 5d c3 } //1
		$a_01_1 = {48 83 ec 28 48 89 1c 24 4c 89 64 24 08 4c 89 6c 24 10 4c 89 74 24 18 4c 89 7c 24 20 48 8b 17 65 48 89 14 25 30 00 00 00 fc e8 d2 f1 fc ff 48 8b 1c 24 4c 8b 64 24 08 4c 8b 6c 24 10 4c 8b 74 24 18 4c 8b 7c 24 20 31 c0 48 83 c4 28 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}