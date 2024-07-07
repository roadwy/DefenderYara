
rule TrojanSpy_Win32_Keylogger_BS{
	meta:
		description = "TrojanSpy:Win32/Keylogger.BS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 72 6f 6a 61 6e 73 6e 74 6c 64 72 2e 64 6c 6c 00 6b 61 6b 61 6a } //1 牴橯湡湳汴牤搮汬欀歡橡
		$a_01_1 = {5b 44 65 6c 65 74 65 5d } //1 [Delete]
		$a_01_2 = {5b 59 61 70 69 73 74 69 72 5d } //1 [Yapistir]
		$a_01_3 = {72 75 6e 2e 62 61 74 } //1 run.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}