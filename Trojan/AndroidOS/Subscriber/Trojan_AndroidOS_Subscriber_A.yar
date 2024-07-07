
rule Trojan_AndroidOS_Subscriber_A{
	meta:
		description = "Trojan:AndroidOS/Subscriber.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_01_0 = {74 69 68 69 70 6d 61 63 68 69 6e 65 6e 69 63 } //2 tihipmachinenic
		$a_01_1 = {6c 61 74 6f 6c 79 6d 70 69 63 62 65 6e 63 68 70 72 6f 78 79 } //2 latolympicbenchproxy
		$a_01_2 = {73 65 61 74 65 64 72 6f 77 6d 61 63 68 69 6e 72 65 70 6f 72 74 65 72 } //2 seatedrowmachinreporter
		$a_01_3 = {69 67 68 61 64 64 75 63 74 6f 72 6d 61 63 68 73 65 71 75 65 6e 63 65 } //2 ighadductormachsequence
		$a_01_4 = {6e 6f 72 68 69 70 61 62 64 75 63 74 6f 72 75 62 75 66 66 65 72 } //2 norhipabductorubuffer
		$a_01_5 = {66 6c 61 74 62 65 6e 63 68 65 6e 74 65 72 6c } //2 flatbenchenterl
		$a_01_6 = {73 6f 66 74 5f 72 65 76 65 72 73 65 63 69 72 } //2 soft_reversecir
		$a_01_7 = {61 72 65 6e 74 5f 6c 65 67 63 75 72 6c 6d 61 } //2 arent_legcurlma
		$a_01_8 = {61 6c 6c 5f 63 61 62 6c 65 63 72 6f 73 73 6e } //2 all_cablecrossn
		$a_01_9 = {74 61 72 79 54 6f 72 73 6f 4d 61 63 68 69 6e } //2 taryTorsoMachin
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=6
 
}