
rule Trojan_MacOS_Amos_X_MTB{
	meta:
		description = "Trojan:MacOS/Amos.X!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 1c 18 4e 10 3c 18 4e 41 02 00 b0 24 f8 c1 3d e4 17 80 3d 04 44 e4 6e 01 00 66 9e 42 02 00 b0 40 00 c2 3d e0 0b 80 3d 20 44 e0 6e 02 3c 18 4e 4e 1c 40 b3 } //1
		$a_01_1 = {b5 73 1a 38 15 9c 68 d3 b5 de 70 d3 b6 ea 00 52 b6 63 1a 38 56 bc 68 d3 82 0c 80 52 c2 02 02 4a a2 53 1a 38 02 bc 70 d3 57 9c 60 d3 e2 02 0e 4a a2 43 1a 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}