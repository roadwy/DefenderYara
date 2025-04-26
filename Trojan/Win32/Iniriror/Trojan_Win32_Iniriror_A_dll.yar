
rule Trojan_Win32_Iniriror_A_dll{
	meta:
		description = "Trojan:Win32/Iniriror.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,39 00 39 00 0c 00 00 "
		
	strings :
		$a_00_0 = {53 52 41 54 2e 64 6c 6c } //20 SRAT.dll
		$a_00_1 = {2e 6b 6c 67 } //3 .klg
		$a_00_2 = {31 32 37 2e 30 2e 30 2e 31 } //3 127.0.0.1
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 35 2e 30 31 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 30 3b 20 4d 79 49 45 20 33 2e 30 31 29 } //3 User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; MyIE 3.01)
		$a_01_4 = {54 57 65 62 43 61 6d 54 68 72 65 61 64 } //3 TWebCamThread
		$a_01_5 = {4e 6f 20 53 68 61 72 65 73 20 46 6f 75 6e 64 } //3 No Shares Found
		$a_01_6 = {43 61 70 74 75 72 65 57 69 6e 64 6f 77 } //1 CaptureWindow
		$a_01_7 = {49 43 53 65 6e 64 4d 65 73 73 61 67 65 } //1 ICSendMessage
		$a_01_8 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_01_9 = {5c 5c 2e 5c 53 4d 41 52 54 56 53 44 } //1 \\.\SMARTVSD
		$a_01_10 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f } //1 Referer: http://
		$a_01_11 = {40 99 89 45 e0 89 55 e4 c7 45 e8 bb bb bb bb c7 45 ec aa aa aa aa 8d 55 e0 b9 10 00 00 00 8b c6 } //20
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*20) >=57
 
}