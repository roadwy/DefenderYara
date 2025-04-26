
rule Adware_MacOS_Pirrit_S_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.S!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 e0 48 83 c0 f0 48 89 c4 48 89 45 b0 48 89 e0 48 83 c0 f0 48 89 c4 48 89 45 c0 48 89 e0 48 83 c0 f0 48 89 c4 48 89 45 a8 b8 a9 08 e2 ef } //1
		$a_01_1 = {8a 45 d7 88 05 02 45 00 00 80 35 fc 44 00 00 10 44 30 25 f6 44 00 00 80 35 f0 44 00 00 39 80 35 ea 44 00 00 79 80 35 e4 44 00 00 08 b0 0f 30 05 dd 44 00 00 80 35 d7 44 00 00 2a 80 35 d1 44 00 00 cc 80 35 cb 44 00 00 44 30 05 c6 44 00 00 80 35 c0 44 00 00 21 b0 c8 30 05 9d 44 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}