
rule Trojan_Win32_ClearEventLogViaWevtutil_A{
	meta:
		description = "Trojan:Win32/ClearEventLogViaWevtutil.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 6e 00 65 00 77 00 2d 00 65 00 76 00 65 00 6e 00 74 00 6c 00 6f 00 67 00 20 00 2d 00 6c 00 6f 00 67 00 6e 00 61 00 6d 00 65 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 [0-08] 20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 61 00 69 00 71 00 } //3
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 77 00 72 00 69 00 74 00 65 00 2d 00 65 00 76 00 65 00 6e 00 74 00 6c 00 6f 00 67 00 20 00 2d 00 6c 00 6f 00 67 00 6e 00 61 00 6d 00 65 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 [0-08] 20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 61 00 69 00 71 00 } //3
		$a_00_2 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 63 00 6c 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 } //3 wevtutil.exe cl attackiq_
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_00_2  & 1)*3) >=3
 
}