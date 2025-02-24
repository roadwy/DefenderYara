
rule Adware_MacOS_Genieo_A_MTB{
	meta:
		description = "Adware:MacOS/Genieo.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 eb ea 03 00 88 45 e7 48 8b 0d a7 eb 06 00 48 8b 35 58 ca 06 00 48 89 cf e8 d2 ea 03 00 48 8b 35 b1 e1 06 00 48 89 c7 e8 c3 ea 03 00 88 45 e6 0f be 55 e7 44 0f be 45 e6 44 39 c2 } //1
		$a_01_1 = {48 89 c7 e8 85 e5 03 00 88 85 97 fe ff ff 48 8b 35 9e e7 06 00 8a 85 97 fe ff ff 48 8b 3d 39 dd 06 00 48 89 bd e0 fd ff ff 48 89 f7 48 8b b5 e0 fd ff ff 0f be d0 e8 52 e5 03 00 48 8b 05 31 e6 06 00 48 8b 35 da c4 06 00 48 89 c7 e8 3c e5 03 00 48 83 f8 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}