
rule TrojanSpy_AndroidOS_DDLight_B{
	meta:
		description = "TrojanSpy:AndroidOS/DDLight.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 4d 61 6e 61 67 65 72 2e 6a 61 76 61 } //01 00  AppManager.java
		$a_01_1 = {6e 65 78 74 49 6e 74 65 72 76 65 6c } //01 00  nextIntervel
		$a_01_2 = {69 6e 74 65 72 76 65 6c } //01 00  intervel
		$a_01_3 = {73 61 76 65 4e 65 78 74 46 65 65 64 62 61 63 6b 54 69 6d 65 } //01 00  saveNextFeedbackTime
		$a_01_4 = {53 75 62 43 6f 6f 70 49 44 } //00 00  SubCoopID
	condition:
		any of ($a_*)
 
}