
rule Adware_MacOS_MaxOfferDeal_A_MTB{
	meta:
		description = "Adware:MacOS/MaxOfferDeal.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 5c 0d a0 66 0f 6f e0 66 0f fc e1 66 0f ef e3 f3 0f 7f 64 0d a0 66 0f fc c2 48 83 c1 10 48 83 f9 35 } //1
		$a_01_1 = {40 30 74 10 04 48 ff c2 48 39 d1 75 f0 c6 44 08 04 00 48 83 c0 04 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}