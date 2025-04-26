
rule Adware_MacOS_Pirrit_O_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.O!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c7 05 07 03 26 00 01 00 00 00 31 ff be 0a 00 00 00 e8 e2 a1 1d 00 48 8d 35 0c 2b 21 00 48 89 c7 e8 d9 a1 1d 00 49 89 c6 31 ff be 0a 00 00 00 e8 c4 a1 1d 00 ff 25 af 33 21 00 } //1
		$a_00_1 = {31 ff be 0a 00 00 00 e8 6b ba 1c 00 48 8d 35 d5 5b 20 00 48 89 c7 e8 62 ba 1c 00 49 89 c7 31 ff be 0a 00 00 00 e8 4d ba 1c 00 48 8d 35 87 5b 20 00 48 89 c7 e8 44 ba 1c 00 48 8d 3d 95 59 20 00 ff d0 49 89 c5 48 8d 3d e4 5a 20 00 41 ff d7 4c 89 ef 48 89 c6 41 ff d4 48 89 c7 e8 d7 ba 1c 00 ff 25 aa 94 20 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}