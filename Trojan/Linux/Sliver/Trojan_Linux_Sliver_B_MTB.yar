
rule Trojan_Linux_Sliver_B_MTB{
	meta:
		description = "Trojan:Linux/Sliver.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 83 ec 18 48 89 6c 24 10 48 8d 6c 24 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 0c f4 ea 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 8b 6c 24 10 48 83 c4 18 c3 } //1
		$a_00_1 = {48 8b 44 24 08 8b 7c 24 10 48 8b 74 24 18 48 8b 54 24 20 55 48 89 e5 48 83 e4 f0 ff d0 48 89 ec 5d c3 } //1
		$a_00_2 = {83 ff 1b 75 f6 b8 00 00 00 00 b9 01 00 00 00 4c 8d 1d 02 23 ee 00 f0 41 0f b1 0b 75 de 48 8b 0d 5c f6 ea 00 4c 8d 05 b5 36 ee 00 4c 8d 0d 0e fa ff ff 48 8b 05 4f f2 ea 00 ff e0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}