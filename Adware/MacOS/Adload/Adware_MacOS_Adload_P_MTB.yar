
rule Adware_MacOS_Adload_P_MTB{
	meta:
		description = "Adware:MacOS/Adload.P!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 31 e4 49 89 dd e8 63 00 00 00 4d 85 e4 74 0a 4c 89 e7 e8 02 a1 00 00 eb 3d 48 8b 3d ad c5 00 00 e8 06 a1 00 00 48 8b 35 b9 c3 00 00 48 89 c7 e8 3d a0 00 00 48 89 c7 e8 4d a0 00 00 48 89 c3 48 8b 35 a7 c3 00 00 48 89 c7 e8 23 a0 00 00 48 89 df e8 27 a0 00 00 31 c0 } //1
		$a_01_1 = {48 83 ec 60 4c 89 65 80 4c 89 6d 88 31 ff e8 88 9d 00 00 48 89 c3 31 ff 48 89 c6 e8 47 9e 00 00 48 8b 40 f8 48 8b 40 40 48 83 c0 0f 48 83 e0 f0 48 89 e1 48 29 c1 48 89 4d b0 48 89 cc 48 89 5d b8 48 8b 43 f8 48 89 45 c0 48 8b 40 40 49 89 e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}