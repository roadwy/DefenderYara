
rule Trojan_BAT_DCRat_DF_MTB{
	meta:
		description = "Trojan:BAT/DCRat.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 0f 11 21 19 58 e0 91 1f 18 62 11 0f 11 21 18 58 e0 91 1f 10 62 60 11 0f 11 21 17 58 e0 91 1e 62 60 11 0f 11 21 e0 91 60 13 06 20 42 00 00 00 fe 0e 32 00 38 47 f4 ff ff } //3
		$a_00_1 = {59 33 72 78 4d 6e 73 50 67 59 53 57 4e 37 6f 49 4c 43 } //3 Y3rxMnsPgYSWN7oILC
		$a_00_2 = {79 74 39 5a 6a 4a 38 38 42 44 5a 51 62 50 41 33 51 61 } //3 yt9ZjJ88BDZQbPA3Qa
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3) >=9
 
}