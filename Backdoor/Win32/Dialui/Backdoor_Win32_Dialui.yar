
rule Backdoor_Win32_Dialui{
	meta:
		description = "Backdoor:Win32/Dialui,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0a 00 00 "
		
	strings :
		$a_01_0 = {44 69 61 6c 55 49 } //5 DialUI
		$a_01_1 = {57 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20 72 65 63 6f 6e 6e 65 63 74 20 74 6f 20 74 68 65 20 69 6e 74 65 72 6e 65 74 3f } //2 Would you like to reconnect to the internet?
		$a_01_2 = {54 69 6d 65 20 6c 69 6d 69 74 20 72 65 61 63 68 65 64 2e 20 20 59 6f 75 20 61 72 65 20 6e 6f 77 20 62 65 69 6e 67 20 64 69 73 63 6f 6e 6e 65 63 74 65 64 } //2 Time limit reached.  You are now being disconnected
		$a_01_3 = {57 65 20 68 6f 70 65 20 79 6f 75 27 76 65 20 65 6e 6a 6f 79 65 64 20 74 68 65 20 67 61 6d 65 73 21 } //2 We hope you've enjoyed the games!
		$a_01_4 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 77 69 6e 74 72 75 73 74 5c 74 72 75 73 74 20 70 72 6f 76 69 64 65 72 73 5c 73 6f 66 74 77 61 72 65 20 70 75 62 6c 69 73 68 69 6e 67 5c 74 72 75 73 74 20 64 61 74 61 62 61 73 65 5c 30 } //2 software\microsoft\windows\currentversion\wintrust\trust providers\software publishing\trust database\0
		$a_01_5 = {75 70 64 61 74 65 2e 70 68 70 } //2 update.php
		$a_01_6 = {20 5b 25 64 25 73 2f 6d 69 6e 5d } //2  [%d%s/min]
		$a_01_7 = {72 65 63 6f 6e 6e 5f 75 72 6c } //2 reconn_url
		$a_01_8 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 32 30 32 30 32 2f 72 65 6d 69 6e 64 2e 68 74 6d 6c } //6 http://127.0.0.1:20202/remind.html
		$a_01_9 = {41 4f 4c 5f 46 72 61 6d 65 32 35 } //2 AOL_Frame25
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*6+(#a_01_9  & 1)*2) >=15
 
}