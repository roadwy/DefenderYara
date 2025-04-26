
rule TrojanSpy_AndroidOS_Vultur_A{
	meta:
		description = "TrojanSpy:AndroidOS/Vultur.A,SIGNATURE_TYPE_DEXHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {57 65 62 56 69 65 77 53 65 72 76 69 63 65 3a 3a 64 6f 57 6f 72 6b } //4 WebViewService::doWork
		$a_00_1 = {63 6f 6e 66 69 67 3a 64 69 61 6c 6f 67 3a 74 69 6d 65 6f 75 74 } //4 config:dialog:timeout
		$a_00_2 = {53 63 72 65 65 6e 4c 6f 63 6b 3a 3a 63 61 70 74 75 72 65 } //4 ScreenLock::capture
		$a_00_3 = {53 63 72 65 65 6e 52 65 63 6f 72 64 53 65 72 76 69 63 65 3a 3a 6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //4 ScreenRecordService::onStartCommand
		$a_00_4 = {2f 42 37 41 56 6e 63 3b } //4 /B7AVnc;
		$a_00_5 = {69 73 43 61 70 74 75 72 65 3d } //1 isCapture=
		$a_00_6 = {72 65 63 6f 72 64 5f 73 63 72 65 65 6e } //1 record_screen
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*4+(#a_00_2  & 1)*4+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=21
 
}