
rule Trojan_Linux_SAgnt_W_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.W!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 50 8b 74 24 10 c7 44 24 0c 00 00 00 00 89 30 31 f6 89 58 04 8b 44 24 0c 89 f2 83 c4 2c 5b 5e 5f 5d c3 0f bd f7 83 f6 1f } //1
		$a_01_1 = {53 89 c3 83 ec 08 8b 40 4c 85 c0 78 0c 83 ec 0c 53 e8 fe e9 ff ff 83 c4 10 8b 43 1c 39 43 14 74 0c 51 6a 00 6a 00 53 ff 53 24 83 c4 10 8b 43 04 8b 53 08 39 d0 } //1
		$a_01_2 = {0f b6 47 0c ba 27 00 00 00 89 c1 83 e1 0f 0f a3 ca 73 75 c0 e8 04 b9 06 04 00 00 0f a3 c1 73 68 66 83 7f 0e 00 74 61 8b 07 83 ec 08 01 e8 50 ff 74 24 50 8b 5c 24 28 e8 84 9c ff ff 83 c4 10 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}