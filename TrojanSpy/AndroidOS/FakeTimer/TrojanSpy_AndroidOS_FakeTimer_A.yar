
rule TrojanSpy_AndroidOS_FakeTimer_A{
	meta:
		description = "TrojanSpy:AndroidOS/FakeTimer.A,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6d 2f 63 68 65 63 6b 2e 70 68 70 3f 69 64 3d } //10 .com/check.php?id=
		$a_01_1 = {2e 63 6f 6d 2f 72 67 73 74 35 2e 70 68 70 } //10 .com/rgst5.php
		$a_01_2 = {26 67 70 73 79 3d } //1 &gpsy=
		$a_01_3 = {2e 63 6f 6d 2f 73 65 6e 64 2e 70 68 70 3f 61 5f 69 64 3d } //1 .com/send.php?a_id=
		$a_01_4 = {4b 69 74 63 68 65 6e 54 69 6d 65 72 53 65 72 76 69 63 65 2e 6a 61 76 61 } //1 KitchenTimerService.java
		$a_03_5 = {26 6d 5f 61 64 64 72 3d ?? ?? 26 74 65 6c 6e 6f 3d } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=13
 
}