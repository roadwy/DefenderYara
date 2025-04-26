
rule Trojan_AndroidOS_Coper_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 58 43 5f 48 49 44 45 5f 49 4e 54 } //1 EXC_HIDE_INT
		$a_01_1 = {76 65 72 69 66 79 61 70 70 73 73 65 74 74 69 6e 67 73 61 63 74 69 76 69 74 79 } //1 verifyappssettingsactivity
		$a_01_2 = {61 63 73 62 5f 70 61 67 65 73 } //1 acsb_pages
		$a_01_3 = {69 6e 6a 5f 61 63 73 62 } //1 inj_acsb
		$a_01_4 = {45 58 43 5f 53 4d 41 52 54 53 5f 53 48 4f 57 } //1 EXC_SMARTS_SHOW
		$a_01_5 = {69 6e 6a 65 63 74 73 5f 74 6f 5f 64 69 73 61 62 6c 65 } //1 injects_to_disable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}