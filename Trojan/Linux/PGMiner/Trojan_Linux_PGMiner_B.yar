
rule Trojan_Linux_PGMiner_B{
	meta:
		description = "Trojan:Linux/PGMiner.B,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 3d 70 6f 73 74 67 72 65 73 } //1 user=postgres
		$a_01_1 = {43 4f 50 59 20 } //1 COPY 
		$a_01_2 = {20 46 52 4f 4d 20 50 52 4f 47 52 41 4d 20 } //1  FROM PROGRAM 
		$a_01_3 = {2f 74 6d 70 2f 2e 49 43 45 2d 75 6e 69 78 } //5 /tmp/.ICE-unix
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5) >=8
 
}