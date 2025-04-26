
rule TrojanSpy_AndroidOS_DDLight_B{
	meta:
		description = "TrojanSpy:AndroidOS/DDLight.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 4d 61 6e 61 67 65 72 2e 6a 61 76 61 } //1 AppManager.java
		$a_01_1 = {6e 65 78 74 49 6e 74 65 72 76 65 6c } //1 nextIntervel
		$a_01_2 = {69 6e 74 65 72 76 65 6c } //1 intervel
		$a_01_3 = {73 61 76 65 4e 65 78 74 46 65 65 64 62 61 63 6b 54 69 6d 65 } //1 saveNextFeedbackTime
		$a_01_4 = {53 75 62 43 6f 6f 70 49 44 } //1 SubCoopID
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}