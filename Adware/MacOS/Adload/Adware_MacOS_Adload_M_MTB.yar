
rule Adware_MacOS_Adload_M_MTB{
	meta:
		description = "Adware:MacOS/Adload.M!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 8b 15 89 24 00 00 48 85 d2 75 1d 48 8b 3d f5 20 00 00 48 8b 35 e6 20 00 00 e8 d9 1b 00 00 48 89 c2 48 89 05 67 24 00 00 48 8b 35 d0 20 00 00 31 ff e8 2b 1b 00 00 49 89 c5 48 85 d2 75 07 4c 89 2d 42 24 00 00 48 89 5d c0 } //1
		$a_00_1 = {48 85 c0 75 2d 48 8b 05 cd 1b 00 00 48 89 85 d8 fe ff ff 48 8d 8d d8 fe ff ff bf 01 00 00 00 31 f6 ba 01 00 00 00 e8 7a 16 00 00 48 89 05 27 1f 00 00 48 8b 15 70 1b 00 00 48 8d bd 20 ff ff ff 48 8d b5 e0 fe ff ff 41 b8 06 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}