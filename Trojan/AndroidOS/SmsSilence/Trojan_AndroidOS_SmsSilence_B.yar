
rule Trojan_AndroidOS_SmsSilence_B{
	meta:
		description = "Trojan:AndroidOS/SmsSilence.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 72 38 38 39 2e 63 6f 6d 2f 41 6e 64 72 6f 69 64 5f 53 4d 53 2f (69 6e 73 74 61 6c 6c 69 6e 67|72 65 63 65 69 76 69 6e 67) 2e 70 68 70 00 } //1
		$a_01_1 = {63 61 74 63 68 73 6d 73 32 2e 6a 61 76 61 00 } //1
		$a_01_2 = {68 67 7a 7a 67 2e 63 6f 6d 2f 6d 73 2e 61 70 6b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}