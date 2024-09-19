
rule Trojan_Win32_SuspGolang_MA{
	meta:
		description = "Trojan:Win32/SuspGolang.MA,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {2e 4d 69 6e 69 44 75 6d 70 49 4f 43 61 6c 6c 62 61 63 6b } //1 .MiniDumpIOCallback
		$a_81_1 = {2e 4d 69 6e 69 44 75 6d 70 43 61 6c 6c 62 61 63 6b 49 6e 70 75 74 } //1 .MiniDumpCallbackInput
		$a_81_2 = {29 2e 54 6f 50 72 6f 74 6f 62 75 66 } //1 ).ToProtobuf
		$a_81_3 = {44 4e 53 42 6c 6f 63 6b 48 65 61 64 65 72 29 2e } //1 DNSBlockHeader).
		$a_81_4 = {48 54 54 50 53 65 73 73 69 6f 6e 49 6e 69 74 29 2e } //1 HTTPSessionInit).
		$a_81_5 = {53 63 72 65 65 6e 73 68 6f 74 52 65 71 29 2e } //1 ScreenshotReq).
		$a_81_6 = {53 63 72 65 65 6e 73 68 6f 74 29 2e } //1 Screenshot).
		$a_81_7 = {53 74 61 72 74 53 65 72 76 69 63 65 52 65 71 29 2e } //1 StartServiceReq).
		$a_81_8 = {53 65 72 76 69 63 65 49 6e 66 6f 29 2e } //1 ServiceInfo).
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}