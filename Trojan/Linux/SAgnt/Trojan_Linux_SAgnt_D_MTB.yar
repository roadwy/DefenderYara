
rule Trojan_Linux_SAgnt_D_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 24 00 18 03 00 74 13 10 1d 16 89 47 c1 57 23 a5 ea 63 bc 5d a3 8b 89 f8 fd 2a 56 96 16 a1 0f 69 51 47 2a 01 37 ec 10 6d b8 e3 e4 10 9f 3e 27 be 82 81 94 d9 e7 33 a5 65 6d 7a b8 7f 6a 5a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}