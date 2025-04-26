
rule Adware_MacOS_Pirrit_T_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.T!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 3d eb b5 09 00 e8 48 0b 08 00 49 89 c6 48 8d 3d 14 b6 09 00 e8 63 0b 08 00 4c 89 f7 48 89 c6 ff 15 03 16 09 00 48 8d 3d e4 b5 09 00 e8 21 0b 08 00 48 8d 3d b8 b5 09 00 e8 15 0b 08 00 49 89 c6 48 8d 3d e1 b5 09 00 e8 30 0b 08 00 4c 89 f7 48 89 c6 } //1
		$a_01_1 = {66 0f 3a 20 c0 02 8a 05 c8 b3 09 00 34 ae 88 05 d4 b3 09 00 8a 05 bb b3 09 00 8d 0c 00 80 e1 20 28 c8 04 10 88 05 bf b3 09 00 8a 05 a6 b3 09 00 34 a0 88 05 b2 b3 09 00 8a 05 99 b3 09 00 89 c1 f6 d1 80 c9 d7 0c 28 20 c8 8a 0d 8d b3 09 00 89 ca f6 d2 80 c9 66 80 ca 99 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}