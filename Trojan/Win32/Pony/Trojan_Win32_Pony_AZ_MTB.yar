
rule Trojan_Win32_Pony_AZ_MTB{
	meta:
		description = "Trojan:Win32/Pony.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {2f 63 72 65 61 74 65 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 74 6e } //1 /create /sc MINUTE /tn
		$a_81_1 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //1 [InternetShortcut]
		$a_81_2 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //1 :Zone.Identifier
		$a_81_3 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c 20 22 } //1 /C choice /C Y /N /D Y /T 3 & Del "
		$a_81_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {64 72 69 76 65 72 73 5c 76 6d 68 67 66 73 2e 73 79 73 } //1 drivers\vmhgfs.sys
		$a_81_6 = {5c 64 72 69 76 65 72 73 5c 76 6d 6d 6f 75 73 65 2e 73 79 73 } //1 \drivers\vmmouse.sys
		$a_81_7 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 SELECT * FROM Win32_VideoController
		$a_81_8 = {56 69 72 74 75 61 6c 42 6f 78 20 47 72 61 70 68 69 63 73 20 41 64 61 70 74 65 72 } //1 VirtualBox Graphics Adapter
		$a_81_9 = {56 4d 77 61 72 65 20 53 56 47 41 20 49 49 } //1 VMware SVGA II
		$a_81_10 = {54 61 6d 70 65 72 50 72 6f 74 65 63 74 69 6f 6e } //1 TamperProtection
		$a_81_11 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_81_12 = {44 69 73 61 62 6c 65 53 63 72 69 70 74 53 63 61 6e 6e 69 6e 67 } //1 DisableScriptScanning
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}