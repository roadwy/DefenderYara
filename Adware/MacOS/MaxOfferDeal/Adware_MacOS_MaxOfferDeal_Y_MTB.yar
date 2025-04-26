
rule Adware_MacOS_MaxOfferDeal_Y_MTB{
	meta:
		description = "Adware:MacOS/MaxOfferDeal.Y!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 56 53 49 89 f6 48 89 fb 48 83 c7 20 48 8b 76 20 ba 08 00 00 00 e8 b8 c9 01 00 48 83 c3 28 49 8b 76 28 48 89 df ba 08 00 00 00 5b 41 5e 5d e9 9f c9 01 00 } //1
		$a_01_1 = {55 48 89 e5 41 57 41 56 53 50 48 89 f3 49 89 fe 48 8b 7e 20 4c 8b 3d 08 b1 02 00 41 ff d7 48 8b 7b 28 41 ff d7 49 83 c6 30 48 8b 73 30 4c 89 f7 ba 07 00 00 00 e8 a5 b1 01 00 48 8b 7b 38 4c 89 f8 48 83 c4 08 5b 41 5e 41 5f 5d ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}