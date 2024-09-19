
rule Trojan_AndroidOS_Smspay_E{
	meta:
		description = "Trojan:AndroidOS/Smspay.E,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 65 6c 6c 20 49 20 63 61 6e 27 74 20 64 6f 20 61 6e 79 74 68 69 6e 67 20 75 6e 74 69 6c 6c 20 79 6f 75 20 70 65 72 6d 69 74 20 6d 65 } //1 Well I can't do anything untill you permit me
		$a_01_1 = {54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 70 65 72 6d 69 73 73 69 6f 6e 21 } //1 Thank you for permission!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}