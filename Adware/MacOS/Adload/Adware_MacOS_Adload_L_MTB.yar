
rule Adware_MacOS_Adload_L_MTB{
	meta:
		description = "Adware:MacOS/Adload.L!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 85 5d d0 0f 84 a2 01 00 00 48 8d 43 ff 4c 21 e8 48 83 c0 20 42 8a 14 20 80 e2 c0 4c 89 e1 80 fa 80 0f 84 95 01 00 00 48 89 c8 48 c1 e0 10 4c 39 e1 4c 0f 45 f8 eb 44 } //1
		$a_00_1 = {75 05 49 89 c4 eb 13 49 c1 e6 02 4c 89 f8 48 c1 e8 0e 4c 39 f0 75 09 45 31 e4 4c 8b 75 d0 eb 19 4c 89 ff 48 c1 ef 10 4c 8b 75 d0 4c 89 f6 4c 89 ea } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}