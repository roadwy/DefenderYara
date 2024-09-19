
rule Adware_MacOS_MaxOfferDeal_B_MTB{
	meta:
		description = "Adware:MacOS/MaxOfferDeal.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 89 c6 48 8d 4d c8 48 ?? ?? ?? c9 22 00 00 8b 45 d4 83 c0 01 89 45 d4 e9 ?? ?? ?? ?? 48 89 45 e8 89 55 e4 } //1
		$a_03_1 = {31 c0 89 c6 48 8d 4d f0 48 ?? ?? ?? e0 21 00 00 31 c0 89 c6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}