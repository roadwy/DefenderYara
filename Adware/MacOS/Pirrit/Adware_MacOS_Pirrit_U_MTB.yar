
rule Adware_MacOS_Pirrit_U_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.U!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 89 f7 ff 15 82 be 20 00 ff 25 04 4a 21 00 48 8b 3b ff 15 73 be 20 00 4c 8b 33 eb e3 } //1
		$a_01_1 = {88 05 1c 2d 21 00 8a 0d 07 2d 21 00 80 f1 5a 88 0d 0e 2d 21 00 8a 0d f9 2c 21 00 80 f1 58 88 0d 00 2d 21 00 8a 0d eb 2c 21 00 8d 14 09 80 e2 64 28 d1 80 c1 32 88 0d ea 2c 21 00 8a 0d d5 2c 21 00 80 f1 df 88 0d dc 2c 21 00 8a 0d d7 2c 21 00 80 f1 47 88 0d d1 2c 21 00 8a 0d c9 2c 21 00 80 f1 bb 88 0d c3 2c 21 00 8a 0d bb 2c 21 00 80 f1 53 88 0d b5 2c 21 00 ff 25 e9 34 21 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}