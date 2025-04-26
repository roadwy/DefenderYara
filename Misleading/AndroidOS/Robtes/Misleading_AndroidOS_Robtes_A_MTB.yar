
rule Misleading_AndroidOS_Robtes_A_MTB{
	meta:
		description = "Misleading:AndroidOS/Robtes.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 6b 70 70 2e 68 74 6d 6c } //1 /lkpp.html
		$a_01_1 = {4d 79 49 6e 73 65 72 74 53 65 72 76 69 63 65 } //1 MyInsertService
		$a_01_2 = {73 74 6f 70 53 65 6c 66 } //1 stopSelf
		$a_01_3 = {4d 61 69 6e 57 65 62 56 69 65 77 43 6c 69 65 6e 74 } //1 MainWebViewClient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}