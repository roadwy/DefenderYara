
rule Trojan_Linux_Kaiji_E_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 10 9a e5 01 00 5d e1 33 00 00 9a 10 e0 2d e5 d4 00 9f e5 04 00 8d e5 0a 2e 00 eb 08 30 9d e5 05 00 a0 e3 04 00 83 e5 c0 10 9f e5 00 10 83 e5 bc 10 9f e5 08 10 83 e5 14 00 83 e5 b4 00 9f e5 10 00 83 e5 b0 00 9f e5 18 00 83 e5 02 00 a0 e3 } //1
		$a_01_1 = {9e e6 00 eb c4 03 9f e5 04 00 8d e5 10 10 a0 e3 08 10 8d e5 f1 e8 00 eb 30 00 9d e5 04 00 8d e5 28 00 9d e5 01 00 40 e2 08 00 8d e5 eb e8 00 eb 9c 03 9f e5 04 00 8d e5 20 10 a0 e3 08 10 8d e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}