
rule TrojanSpy_AndroidOS_Ahmyth_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 65 72 6d 69 73 53 63 72 65 65 6e } //1 PermisScreen
		$a_01_1 = {46 4b 50 69 6e 53 63 72 65 65 6e } //1 FKPinScreen
		$a_01_2 = {41 4d 53 55 6e 73 74 6f 70 61 62 6c 6c 65 } //1 AMSUnstopablle
		$a_01_3 = {44 75 63 6b 44 75 63 6b 2e 6b 74 } //1 DuckDuck.kt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}