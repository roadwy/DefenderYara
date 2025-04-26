
rule TrojanSpy_Win32_Banker_APH{
	meta:
		description = "TrojanSpy:Win32/Banker.APH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 32 32 00 } //1
		$a_03_1 = {54 6f 64 6f 73 [0-10] 53 59 53 54 45 4d } //1
		$a_01_2 = {47 62 70 53 76 2e 65 78 65 22 20 2f 54 20 2f 45 20 2f 43 20 2f 50 } //1 GbpSv.exe" /T /E /C /P
		$a_01_3 = {77 73 66 74 70 72 70 36 34 2e 73 79 73 22 20 2f 54 20 2f 45 20 2f 43 20 2f 50 } //1 wsftprp64.sys" /T /E /C /P
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}