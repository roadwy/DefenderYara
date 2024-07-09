
rule TrojanSpy_AndroidOS_Banker_XO{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.XO,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {91 02 05 04 35 21 0f 00 62 02 [0-02] 90 (4a 02 02 03|b7) 62 8e 22 50 02 00 01 d8 01 01 01 28 f0 } //1
		$a_00_1 = {50 65 72 69 6f 64 69 63 4a 6f 62 53 65 72 76 69 63 65 } //1 PeriodicJobService
		$a_00_2 = {49 6e 6a 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //1 InjAccessibilityService
		$a_00_3 = {53 63 72 65 65 6e 63 61 73 74 53 65 72 76 69 63 65 } //1 ScreencastService
		$a_00_4 = {4c 6f 63 6b 65 72 41 63 74 69 76 69 74 79 } //1 LockerActivity
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}