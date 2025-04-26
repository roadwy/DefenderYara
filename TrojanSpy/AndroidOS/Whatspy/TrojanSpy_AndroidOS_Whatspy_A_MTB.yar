
rule TrojanSpy_AndroidOS_Whatspy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Whatspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 41 70 70 49 63 6f 6e } //1 hideAppIcon
		$a_00_1 = {4c 63 6f 6d 2f 6e 6f 74 69 66 69 65 72 2f 68 69 64 64 65 6e } //1 Lcom/notifier/hidden
		$a_00_2 = {6e 6f 74 69 66 69 65 72 2e 6c 6f 67 } //1 notifier.log
		$a_00_3 = {4c 63 6f 6d 2f 69 6e 74 65 72 6e 61 6c 61 70 70 2f 6c 6f 67 67 65 72 } //1 Lcom/internalapp/logger
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}