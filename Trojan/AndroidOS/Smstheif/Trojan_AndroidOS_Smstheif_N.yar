
rule Trojan_AndroidOS_Smstheif_N{
	meta:
		description = "Trojan:AndroidOS/Smstheif.N,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 65 72 73 39 69 6a 59 54 6d 73 61 73 32 6d 4c 41 64 73 73 73 73 73 } //1 cers9ijYTmsas2mLAdsssss
		$a_01_1 = {75 64 61 6c 73 6e 62 72 46 64 64 5a 64 73 69 73 71 70 } //1 udalsnbrFddZdsisqp
		$a_01_2 = {73 66 6d 6d 62 75 71 6b 68 62 74 71 68 65 68 } //1 sfmmbuqkhbtqheh
		$a_01_3 = {74 61 6d 73 6b 77 74 77 6f 64 65 77 69 6b } //1 tamskwtwodewik
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}