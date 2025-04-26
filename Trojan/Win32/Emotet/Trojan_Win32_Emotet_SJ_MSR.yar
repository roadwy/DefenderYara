
rule Trojan_Win32_Emotet_SJ_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SJ!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 63 6b 57 69 6e 64 6f 77 55 70 64 61 74 65 } //1 LockWindowUpdate
		$a_01_1 = {44 00 6f 00 63 00 73 00 48 00 69 00 73 00 74 00 6f 00 72 00 79 00 } //1 DocsHistory
		$a_01_2 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_01_3 = {52 65 73 74 72 69 63 74 52 75 6e } //1 RestrictRun
		$a_01_4 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 NoRecentDocsHistory
		$a_01_5 = {45 00 72 00 61 00 73 00 65 00 20 00 65 00 76 00 65 00 72 00 79 00 74 00 68 00 69 00 6e 00 67 00 } //1 Erase everything
		$a_01_6 = {4f 00 70 00 65 00 6e 00 20 00 74 00 68 00 69 00 73 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //1 Open this document
		$a_01_7 = {44 00 49 00 42 00 4c 00 4f 00 4f 00 4b 00 } //1 DIBLOOK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}