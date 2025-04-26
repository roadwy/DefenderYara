
rule Trojan_Win64_Crnoash_A{
	meta:
		description = "Trojan:Win64/Crnoash.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 42 01 b9 1f 00 00 00 ba 01 00 00 00 2b c8 41 0f b6 02 49 83 c2 02 d3 e2 b9 1f 00 00 00 2b c8 b8 01 00 00 00 d3 e0 0b d0 44 0b ca 49 83 eb 01 75 cc 48 8d 15 } //1
		$a_01_1 = {48 8b 5b 10 ba 26 80 ac c8 48 8b cb e8 55 fe ff ff ba ee ea c0 1f 48 8b cb 4c 8b f0 e8 45 fe ff ff 83 7e 10 00 4c 8b e8 0f 84 93 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}