
rule Adware_MacOS_MaxOfferDeal_G_MTB{
	meta:
		description = "Adware:MacOS/MaxOfferDeal.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 df 48 8b 35 ec 4a 03 00 41 ff d7 48 ff c8 4c 39 e0 76 50 48 89 df 48 8b 75 b0 4c 89 e2 41 ff d7 48 89 c7 e8 e8 01 02 00 49 89 c6 48 89 c7 48 8b 75 b8 41 ff d7 48 98 48 8d 0d 46 84 02 00 0f be 0c 08 48 8b 7d d0 4c 89 ee 48 8d 15 3c 04 03 00 31 c0 41 ff d7 4c 89 f7 ff 15 46 fa 02 00 49 ff c4 eb 9b } //1
		$a_01_1 = {48 89 df 48 8b 1d 37 fa 02 00 ff d3 48 8b 7d c0 ff d3 48 8b 7d d0 48 83 c4 28 5b 41 5c 41 5d 41 5e 41 5f 5d e9 24 01 02 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}