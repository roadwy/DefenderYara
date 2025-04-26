
rule Trojan_AndroidOS_SMSSend_C{
	meta:
		description = "Trojan:AndroidOS/SMSSend.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 72 65 67 2f 4d 61 69 6e 52 65 67 41 63 74 69 76 69 74 79 } //1 Lcom/reg/MainRegActivity
		$a_01_1 = {6e 65 65 64 53 68 6f 77 4c 69 6e 6b 46 6f 72 6d } //1 needShowLinkForm
		$a_01_2 = {64 69 73 70 6c 61 79 46 61 6b 65 50 72 6f 67 72 65 73 73 } //1 displayFakeProgress
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}