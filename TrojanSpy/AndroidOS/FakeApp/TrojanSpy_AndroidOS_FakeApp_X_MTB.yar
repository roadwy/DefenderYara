
rule TrojanSpy_AndroidOS_FakeApp_X_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 71 69 6e 79 75 65 2f 76 6d 61 69 6e 2f 61 63 74 69 76 69 74 79 } //1 com/qinyue/vmain/activity
		$a_03_1 = {c2 07 00 0c 01 62 02 ?? ?? 12 03 12 04 12 05 12 06 74 06 ?? 02 01 00 0c 00 38 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}