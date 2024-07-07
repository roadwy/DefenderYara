
rule Trojan_AndroidOS_ScamApp_B_MTB{
	meta:
		description = "Trojan:AndroidOS/ScamApp.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {47 65 74 20 90 02 04 20 64 61 69 6c 79 20 70 61 79 74 6d 20 63 61 73 68 90 02 04 44 6f 77 6e 6c 6f 61 64 20 74 68 65 20 61 70 70 90 00 } //1
		$a_00_1 = {52 75 70 65 65 73 20 46 72 65 65 20 70 61 79 74 6d 20 63 61 73 68 20 6a 75 73 74 20 6a 75 73 74 20 62 79 20 77 6f 72 6b 69 6e 67 20 6f 6e 20 79 6f 75 72 20 70 68 6f 6e 65 } //1 Rupees Free paytm cash just just by working on your phone
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}