
rule Trojan_Win32_FireStream_A_dha{
	meta:
		description = "Trojan:Win32/FireStream.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 7b 7d 20 2f 74 72 20 22 7b 7d 22 20 2f 73 63 20 7b 7d 20 2f 6d 6f 20 7b 7d 20 2f 72 75 20 7b 7d 20 2f 66 } //1 schtasks /create /tn {} /tr "{}" /sc {} /mo {} /ru {} /f
		$a_01_1 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 22 20 2f 76 20 22 53 65 74 75 70 45 78 65 63 75 74 65 22 } //1 reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "SetupExecute"
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 66 20 2f 74 20 30 } //1 shutdown /r /f /t 0
		$a_01_3 = {66 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 73 63 68 65 64 75 6c 65 64 20 74 61 73 6b } //1 failed to create scheduled task
		$a_01_4 = {66 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 72 65 67 69 73 74 72 79 20 6b 65 79 73 } //1 failed to write registry keys
		$a_01_5 = {66 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 66 69 6c 65 } //1 failed to write file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}