
rule Adware_MacOS_Adload_O_MTB{
	meta:
		description = "Adware:MacOS/Adload.O!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 66 23 00 00 84 c0 75 2e 48 8b 3d 93 32 00 00 ba 01 00 00 00 b9 01 00 00 00 4c 89 f6 e8 d3 23 00 00 48 89 d1 48 8d 15 a5 07 00 00 48 89 df 48 89 c6 e8 f8 22 00 00 48 8d 3d 49 29 00 00 e8 64 23 00 00 48 89 c3 } //1
		$a_01_1 = {74 12 48 8d 35 bd 0d 00 00 48 89 c7 e8 d4 20 00 00 48 89 c1 48 89 0d 4a 32 00 00 48 8b 35 43 2f 00 00 4c 89 f7 e8 61 20 00 00 48 85 c0 74 12 48 8d 35 a3 0d 00 00 48 89 c7 e8 a7 20 00 00 48 89 c3 48 89 1d 25 32 00 00 48 8d 3d bf 26 00 00 e8 9d 20 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}