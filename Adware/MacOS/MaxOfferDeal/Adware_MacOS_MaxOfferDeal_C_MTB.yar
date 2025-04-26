
rule Adware_MacOS_MaxOfferDeal_C_MTB{
	meta:
		description = "Adware:MacOS/MaxOfferDeal.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 49 89 f4 89 7d cc 4c 63 ef 31 db } //1
		$a_03_1 = {4c 89 ff 41 ?? ?? 48 8b 7d c8 41 ?? ?? 48 8b 7d c0 41 ?? ?? 41 0f b6 c6 48 83 c4 28 5b 41 5c 41 5d 41 5e 41 5f 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}