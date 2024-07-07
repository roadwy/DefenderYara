
rule Trojan_Win32_Vundo_gen_O{
	meta:
		description = "Trojan:Win32/Vundo.gen!O,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 } //1 \Windows NT\CurrentVersion\Winlogon\Notify
		$a_01_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //1 CurrentVersion\Explorer\Browser Helper Objects\
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 5c } //1 Software\Microsoft\Internet Account Manager\Accounts\
		$a_01_3 = {3c 72 65 64 69 72 65 63 74 3e 3c 00 6b 00 65 00 79 00 77 00 6f 00 72 00 64 00 73 } //1
		$a_01_4 = {57 6f 72 6b 65 72 41 00 57 6f 72 6b 65 72 57 } //1
		$a_01_5 = {67 5f 50 6f 70 75 70 50 65 72 44 61 79 } //1 g_PopupPerDay
		$a_01_6 = {67 5f 43 6f 6e 6e 65 63 74 69 6f 6e 50 65 72 44 61 79 } //1 g_ConnectionPerDay
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}