
rule Adware_MacOS_Pirrit_Y_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.Y!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {9c d4 00 00 34 60 88 05 9a d4 00 00 8a 05 8f d4 00 00 8d 0c 00 80 e1 6a 28 c8 04 35 88 05 85 d4 00 00 8a 05 7a d4 00 00 34 ec 88 05 78 d4 00 00 8a 05 6d d4 00 00 89 c1 f6 d1 80 c9 21 0c de 20 c8 88 05 62 d4 00 00 8a 05 5d d4 00 00 34 2b } //1
		$a_01_1 = {80 e1 58 28 c8 04 2c 88 05 f9 d0 00 00 8a 05 e8 d0 00 00 34 6e 88 05 ec d0 00 00 b8 3b d4 82 1b 33 05 e2 d0 00 00 89 05 ec d0 00 00 8a 05 da d0 00 00 34 09 88 05 e2 d0 00 00 8a 05 cd d0 00 00 34 91 88 05 d5 d0 00 00 8a 05 c0 d0 00 00 88 05 ca d0 00 00 8a 05 b5 d0 00 00 34 d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}