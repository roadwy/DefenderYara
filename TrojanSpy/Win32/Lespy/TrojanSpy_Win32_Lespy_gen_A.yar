
rule TrojanSpy_Win32_Lespy_gen_A{
	meta:
		description = "TrojanSpy:Win32/Lespy.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 65 68 74 74 70 73 65 6e 64 72 65 71 75 65 73 74 6d 75 74 65 78 5f 25 75 } //2 iehttpsendrequestmutex_%u
		$a_01_1 = {69 64 3d 25 30 38 6c 58 25 30 38 6c 58 26 69 70 3d 25 73 26 74 69 74 6c 65 3d 25 73 26 75 72 6c 3d 25 73 26 64 61 74 61 } //2 id=%08lX%08lX&ip=%s&title=%s&url=%s&data
		$a_01_2 = {7b 65 33 61 37 32 39 64 61 2d 65 61 62 63 2d 64 66 35 30 2d 31 38 34 32 2d 64 66 64 36 38 32 36 34 34 33 31 31 7d } //2 {e3a729da-eabc-df50-1842-dfd682644311}
		$a_01_3 = {6d 79 63 6c 6f 73 65 65 76 65 6e 74 67 6c 6f 62 61 66 72 61 6d 65 72 6c 31 } //2 mycloseeventglobaframerl1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}