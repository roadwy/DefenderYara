
rule Trojan_Win32_Aphidma_B{
	meta:
		description = "Trojan:Win32/Aphidma.B,SIGNATURE_TYPE_PEHSTR,33 00 33 00 08 00 00 "
		
	strings :
		$a_01_0 = {32 30 39 2e 31 36 30 2e 32 31 2e 37 36 } //10 209.160.21.76
		$a_01_1 = {6b 6f 6c 6f 72 6f 64 69 75 6d 73 65 6e 2e 63 6f 6d } //1 kolorodiumsen.com
		$a_01_2 = {69 6e 74 65 72 66 69 75 6d 73 65 6e 2e 63 6f 6d } //1 interfiumsen.com
		$a_01_3 = {6b 72 69 63 6b 65 74 70 6c 6f 69 65 73 2e 63 6f 6d } //1 kricketploies.com
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 63 73 66 64 6c 6c } //10 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\csfdll
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 63 72 79 70 74 33 32 73 65 74 } //10 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\crypt32set
		$a_01_6 = {49 20 61 6d 20 49 6e 73 74 61 6c 6c 65 64 } //10 I am Installed
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //10 Software\Microsoft\Internet Account Manager\Accounts
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10) >=51
 
}