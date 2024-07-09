
rule Backdoor_Linux_Gafgyt_CR_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {3b 8c 89 e2 51 8b 18 8b 48 04 83 c1 0c 60 47 e8 d0 04 ?? ?? 89 c6 89 fa f6 5f 6b 6f ?? ?? 89 02 0b 37 30 58 59 5f 5b 56 e7 9d fb f7 ff 52 57 ?? ?? 6a 02 5e 6a 01 5a b9 ee 29 db 68 c0 96 a4 5b 3f } //1
		$a_03_1 = {05 08 00 74 fd bf b7 ff 0c eb 31 83 c0 04 a3 24 f0 0c ?? d2 a1 06 8b 10 85 d2 75 eb b8 00 ef df 7e db 00 85 c0 1f c7 04 24 64 e9 15 e8 05 7f fb f7 c6 05 34 7d e7 f7 fb 01 c9 c3 8d b6 1e 8d bf 05 55 b8 54 18 77 ff df ff 77 88 } //1
		$a_03_2 = {80 3d e0 e3 05 08 00 74 fd bf b7 ff 0c eb 35 83 c0 04 a3 24 e0 0c ff d2 a1 06 8b 10 85 d2 75 eb b8 00 fe 6f df de 00 85 c0 74 10 2b ?? ?? 04 dc 16 e8 04 7f ?? ?? 83 c4 10 c6 05 2c f6 bd fd 38 01 c9 53 8d b4 26 24 55 2a 54 b9 ff fd 5f 77 88 5a 81 c2 f4 5e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}