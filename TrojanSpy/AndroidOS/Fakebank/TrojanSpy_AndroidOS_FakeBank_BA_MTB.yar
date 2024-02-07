
rule TrojanSpy_AndroidOS_FakeBank_BA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.BA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,3c 00 3c 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 32 6b 38 79 32 78 35 67 74 38 64 36 73 34 71 } //05 00  12k8y2x5gt8d6s4q
		$a_01_1 = {71 34 73 36 64 38 74 67 35 78 32 79 38 6b 32 6c } //02 00  q4s6d8tg5x2y8k2l
		$a_01_2 = {31 32 6b 38 79 32 } //02 00  12k8y2
		$a_01_3 = {78 35 67 74 38 } //02 00  x5gt8
		$a_01_4 = {64 36 73 34 71 } //02 00  d6s4q
		$a_01_5 = {35 78 32 79 } //02 00  5x2y
		$a_01_6 = {38 6b 32 6c } //32 00  8k2l
		$a_03_7 = {21 52 35 20 90 01 02 da 02 00 02 62 03 90 01 02 48 04 05 00 d5 44 f0 00 e2 04 04 04 49 03 03 04 50 03 01 02 da 02 00 02 d8 02 02 01 62 03 90 01 02 48 04 05 00 dd 04 04 0f 49 03 03 04 50 03 01 02 d8 00 00 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}