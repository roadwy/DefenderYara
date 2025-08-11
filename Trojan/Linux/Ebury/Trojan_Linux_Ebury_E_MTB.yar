
rule Trojan_Linux_Ebury_E_MTB{
	meta:
		description = "Trojan:Linux/Ebury.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 e8 02 31 d2 45 31 c9 45 31 e4 41 c1 e2 02 41 c0 e8 04 44 88 67 01 45 09 d0 44 88 4f 02 83 ea 04 44 88 07 48 83 c6 04 48 83 c7 03 85 d2 0f 8f 9d fe ff ff 5b 5d 41 5c c3 } //2
		$a_01_1 = {89 e8 8b 4b 60 c1 e8 06 23 43 5c 89 c0 48 8b 04 c2 89 ea d3 ea 89 d1 83 e1 3f 48 89 c2 48 d3 ea 89 e9 83 e1 3f 48 d3 e8 48 85 c2 0f 84 44 01 00 00 31 d2 89 e8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}