
rule Trojan_AndroidOS_SmsSilence_A{
	meta:
		description = "Trojan:AndroidOS/SmsSilence.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 74 63 68 73 6d 73 32 2e 6a 61 76 61 00 } //1
		$a_01_1 = {63 61 74 63 68 73 70 61 6d 2f 63 61 74 63 68 73 6d 73 32 3b 00 } //1
		$a_03_2 = {69 74 37 39 38 30 2e 63 6f 6d 2f 41 6e 64 72 6f 69 64 5f 53 4d 53 2f (72 65 63 65 69 76|69 6e 73 74 61 6c 6c) 69 6e 67 2e 70 68 70 } //1
		$a_01_3 = {73 74 61 72 62 75 67 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}