
rule TrojanSpy_AndroidOS_Banker_AP_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AP!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2f 61 70 70 2f [0-08] 2f 41 63 74 69 76 69 74 79 46 69 6c 74 65 72 4d 67 72 } //1
		$a_01_1 = {2f 53 63 72 65 65 6e 53 68 6f 74 53 65 72 76 69 63 65 } //1 /ScreenShotService
		$a_01_2 = {6f 6e 53 74 61 72 74 54 72 61 63 6b 69 6e 67 54 6f 75 63 68 } //1 onStartTrackingTouch
		$a_01_3 = {4f 72 69 65 6e 74 61 74 69 6f 6e 45 76 65 6e 74 4c 69 73 74 65 6e 65 72 } //1 OrientationEventListener
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}