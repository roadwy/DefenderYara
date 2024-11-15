
rule Trojan_Linux_ProcessHider_D_MTB{
	meta:
		description = "Trojan:Linux/ProcessHider.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 54 53 48 83 ec 10 89 7d ec 48 89 75 e0 48 8b 45 e0 48 8b 00 48 89 c7 e8 48 fa ff ff 48 8b 45 e0 48 8d 58 08 48 8b 55 e0 8b 45 ec 48 89 d6 89 c7 e8 73 fb ff ff 48 89 03 48 8b 45 e0 48 83 c0 08 48 8b 00 48 85 c0 74 0a 48 8b 45 e0 4c 8b 60 08 } //1
		$a_01_1 = {83 7b 08 25 48 8b 2b 0f 85 b2 01 00 00 ff 53 10 48 83 c3 18 48 89 45 00 48 81 fb b0 02 40 00 72 df e8 72 05 00 00 48 8b 05 9b 02 2c 00 48 85 c0 0f 84 93 01 00 00 48 8b 10 48 89 d6 48 89 54 24 20 40 80 e6 00 64 48 89 34 25 28 00 00 00 48 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}