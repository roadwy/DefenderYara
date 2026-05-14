
rule Trojan_Win32_CredTheftBin_BB{
	meta:
		description = "Trojan:Win32/CredTheftBin.BB,SIGNATURE_TYPE_PEHSTR,46 00 46 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 } //10 Connecting to Outlook
		$a_01_1 = {43 72 65 64 55 49 50 72 6f 6d 70 74 46 6f 72 57 69 6e 64 6f 77 73 43 72 65 64 65 6e 74 69 61 6c 73 57 } //10 CredUIPromptForWindowsCredentialsW
		$a_01_2 = {43 72 65 64 55 6e 50 61 63 6b 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 42 75 66 66 65 72 57 } //10 CredUnPackAuthenticationBufferW
		$a_01_3 = {43 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00 } //10 C:\users\public\
		$a_01_4 = {2e 00 74 00 78 00 74 00 } //10 .txt
		$a_01_5 = {43 72 65 64 75 69 2e 64 6c 6c } //10 Credui.dll
		$a_01_6 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 74 73 61 70 69 33 32 2e 49 73 49 6e 74 65 72 61 63 74 69 76 65 55 73 65 72 53 65 73 73 69 6f 6e } //10 C:\windows\system32\wtsapi32.IsInteractiveUserSession
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=70
 
}