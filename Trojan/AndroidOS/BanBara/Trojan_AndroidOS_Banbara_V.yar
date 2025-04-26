
rule Trojan_AndroidOS_Banbara_V{
	meta:
		description = "Trojan:AndroidOS/Banbara.V,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 69 63 72 65 64 69 6f 76 } //1 sicrediov
		$a_01_1 = {77 73 73 3a 2f 2f 61 70 69 2e 62 61 6e 61 6e 61 73 70 6c 69 74 2e 73 68 6f 70 2f 77 73 } //1 wss://api.bananasplit.shop/ws
		$a_01_2 = {36 34 39 39 66 66 38 66 62 63 32 66 38 62 63 30 38 64 64 37 33 33 34 32 } //1 6499ff8fbc2f8bc08dd73342
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}