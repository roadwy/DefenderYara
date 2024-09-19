
rule Trojan_Linux_Sliver_C_MTB{
	meta:
		description = "Trojan:Linux/Sliver.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {75 14 48 85 c0 74 09 48 8b 2c 24 48 83 c4 08 c3 e8 d8 b9 fa ff 90 4c 8d 6c 24 10 } //1
		$a_00_1 = {48 85 c0 74 09 48 8b 2c 24 48 83 c4 08 c3 e8 d8 b8 fa ff 90 4c 8d 6c 24 10 4d 39 2c 24 75 e1 49 89 24 24 eb db } //1
		$a_00_2 = {74 21 48 8b 10 48 8b 58 08 0f b6 48 10 0f b6 78 11 48 89 d0 e8 a4 b1 fa ff 48 8b 6c 24 18 48 83 c4 20 c3 e8 d5 b7 fa ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}