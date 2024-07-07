
rule Trojan_AndroidOS_Ermak_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Ermak.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 69 64 65 73 6d 73 } //1 hidesms
		$a_01_1 = {73 65 6e 64 5f 6c 6f 67 5f 69 6e 6a 65 63 74 73 } //1 send_log_injects
		$a_01_2 = {6f 70 65 6e 46 61 6b 65 20 69 6e 6a 65 63 74 } //1 openFake inject
		$a_01_3 = {6b 69 6c 6c 41 70 70 6c 69 63 61 74 69 6f 6e 20 61 64 6d 69 6e } //1 killApplication admin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}