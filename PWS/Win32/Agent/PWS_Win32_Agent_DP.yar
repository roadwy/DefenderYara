
rule PWS_Win32_Agent_DP{
	meta:
		description = "PWS:Win32/Agent.DP,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 73 72 73 65 72 76 69 63 65 } //1 SYSTEM\CurrentControlSet\Services\srservice
		$a_01_1 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_01_2 = {50 4b 31 31 5f 47 65 74 49 6e 74 65 72 6e 61 6c 4b 65 79 53 6c 6f 74 } //1 PK11_GetInternalKeySlot
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 41 64 6f 62 65 5c 53 54 52 } //1 Software\Adobe\STR
		$a_01_4 = {57 4d 5f 48 54 4d 4c 5f 47 45 54 4f 42 4a 45 43 54 } //1 WM_HTML_GETOBJECT
		$a_01_5 = {59 41 48 4f 4f 20 4d 45 53 53 45 4e 47 45 52 } //1 YAHOO MESSENGER
		$a_01_6 = {4d 53 4e 20 4d 45 53 53 45 4e 47 45 52 } //1 MSN MESSENGER
		$a_01_7 = {49 4d 20 73 65 73 73 69 6f 6e 73 } //1 IM sessions
		$a_01_8 = {52 43 50 54 20 54 4f 3a 3c } //1 RCPT TO:<
		$a_01_9 = {50 41 53 53 57 4f 52 44 53 } //1 PASSWORDS
		$a_01_10 = {54 46 54 50 53 65 6e 64 } //1 TFTPSend
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}