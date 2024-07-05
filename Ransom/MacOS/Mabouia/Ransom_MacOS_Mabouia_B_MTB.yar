
rule Ransom_MacOS_Mabouia_B_MTB{
	meta:
		description = "Ransom:MacOS/Mabouia.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 28 4c 8d 45 b0 4c 89 ef 4c 89 e6 4c 89 fa 48 8b 4d a8 4d 89 c7 e8 aa fe ff ff 89 c3 be 20 00 00 00 4c 89 ff e8 c1 8b 00 00 4c 3b 75 d0 } //01 00 
		$a_00_1 = {73 67 40 88 75 b0 c6 45 b1 00 c6 45 b2 01 c6 45 b3 01 c7 45 ec 00 00 00 00 48 c7 45 e4 00 00 00 00 48 c7 45 dc 00 00 00 00 48 c7 45 d4 00 00 00 00 48 c7 45 cc 00 00 00 00 48 c7 45 c4 00 00 00 00 48 c7 45 bc 00 00 00 00 48 c7 45 b4 00 00 00 00 48 8d 75 b0 e8 38 ff ff ff 48 3b 5d f0 75 0e 31 c0 48 83 c4 48 5b 5d c3 e8 e6 81 01 00 } //00 00 
	condition:
		any of ($a_*)
 
}