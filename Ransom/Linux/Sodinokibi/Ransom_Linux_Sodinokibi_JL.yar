
rule Ransom_Linux_Sodinokibi_JL{
	meta:
		description = "Ransom:Linux/Sodinokibi.JL,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 72 72 6f 72 20 63 72 65 61 74 65 20 6e 6f 74 65 20 69 6e 20 64 69 72 20 25 73 } //1 Error create note in dir %s
		$a_01_1 = {70 6b 69 6c 6c } //1 pkill
		$a_01_2 = {8b 55 f0 8b 45 c0 01 d0 c1 c0 07 89 c2 8b 45 e0 31 d0 89 45 e0 8b 55 e0 8b 45 f0 01 d0 c1 c0 09 89 c2 8b 45 d0 31 d0 89 45 d0 8b 55 d0 8b 45 e0 01 d0 c1 c0 0d 89 c2 8b 45 c0 31 d0 89 45 c0 8b 55 c0 8b 45 d0 01 d0 c1 c8 0e } //1
		$a_01_3 = {7b 22 76 65 72 22 3a 25 64 2c 22 70 6b 22 3a 22 25 73 22 2c 22 75 69 64 22 3a 22 25 73 22 2c 22 73 6b 22 3a 22 25 73 22 2c 22 6f 73 22 3a 22 25 73 22 2c 22 65 78 74 22 3a 22 25 73 22 7d } //1 {"ver":%d,"pk":"%s","uid":"%s","sk":"%s","os":"%s","ext":"%s"}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}