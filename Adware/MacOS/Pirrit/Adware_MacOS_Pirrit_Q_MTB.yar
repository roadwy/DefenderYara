
rule Adware_MacOS_Pirrit_Q_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.Q!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c1 80 f1 b3 88 0d f8 d1 04 00 80 35 f2 d1 04 00 55 b1 6a 30 0d eb d1 04 00 80 35 e5 d1 04 00 e5 80 35 df d1 04 00 01 80 35 d9 d1 04 00 16 80 35 d3 d1 04 00 f8 80 35 cd d1 04 00 33 30 0d c8 d1 04 00 } //1
		$a_01_1 = {8a 45 d0 34 69 88 05 fd 30 07 00 b0 f3 30 05 f6 30 07 00 b0 7a 30 05 ef 30 07 00 80 35 ea 30 07 00 37 80 35 e4 30 07 00 55 b1 82 30 0d dd 30 07 00 40 b6 82 80 35 d4 30 07 00 ab 80 35 ce 30 07 00 46 b1 bb 30 0d c7 30 07 00 30 05 c2 30 07 00 80 35 bc 30 07 00 3a 40 b7 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}