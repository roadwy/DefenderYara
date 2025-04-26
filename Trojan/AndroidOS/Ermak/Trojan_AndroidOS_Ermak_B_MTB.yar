
rule Trojan_AndroidOS_Ermak_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Ermak.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 69 65 77 49 6e 6a 65 63 74 69 6f 6e 73 61 64 } //1 ViewInjectionsad
		$a_01_1 = {73 65 6e 64 5f 6c 6f 67 5f 69 6e 6a 65 63 74 73 } //1 send_log_injects
		$a_01_2 = {75 70 64 61 74 65 69 6e 6a 65 63 74 61 6e 64 6c 69 73 74 61 70 70 73 } //1 updateinjectandlistapps
		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 49 6e 6a 65 63 74 69 6f 6e } //1 downloadInjection
		$a_01_4 = {75 70 64 61 74 65 42 6f 74 50 61 72 61 6d 73 } //1 updateBotParams
		$a_01_5 = {75 70 64 61 74 65 42 6f 74 53 75 62 49 6e 66 6f } //1 updateBotSubInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}