
rule Trojan_Linux_BackConn_A_MTB{
	meta:
		description = "Trojan:Linux/BackConn.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 0a 5e 31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 9b 5e ec a0 68 02 00 1f a7 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27 } //1
		$a_01_1 = {b2 07 b9 00 10 00 00 89 e3 c1 eb 0c c1 e3 0c b0 7d cd 80 85 c0 78 10 5b 89 e1 99 b6 0c b0 03 cd 80 85 c0 78 02 ff e1 b8 01 00 00 00 bb 01 00 00 00 cd 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}