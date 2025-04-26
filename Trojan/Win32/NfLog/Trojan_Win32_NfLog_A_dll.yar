
rule Trojan_Win32_NfLog_A_dll{
	meta:
		description = "Trojan:Win32/NfLog.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 72 6f 63 47 6f 00 00 4e 66 4c 6f 67 2f 4e 66 69 6c 65 2e 61 73 70 00 } //1
		$a_00_1 = {53 76 63 48 6f 73 74 44 4c 4c 2e 65 78 65 } //1 SvcHostDLL.exe
		$a_00_2 = {53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 System32\svchost.exe -k netsvcs
		$a_00_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 65 72 76 69 63 65 44 6c 6c 29 } //1 RegSetValueEx(ServiceDll)
		$a_01_4 = {4e 66 63 6f 72 65 4f 6b 00 } //1
		$a_01_5 = {53 76 63 57 69 6e 65 74 2e 65 78 65 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}