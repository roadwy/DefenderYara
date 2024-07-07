
rule Trojan_Win32_Sdum_EM_MTB{
	meta:
		description = "Trojan:Win32/Sdum.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {69 70 63 6f 6e 66 69 67 20 2f 72 65 6c 65 61 73 65 20 26 20 69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73 20 26 20 69 70 63 6f 6e 66 69 67 20 2f 72 65 6e 65 77 } //1 ipconfig /release & ipconfig /flushdns & ipconfig /renew
		$a_81_1 = {73 68 75 74 64 6f 77 6e 20 2f 73 20 2f 74 20 32 39 20 2f 63 } //1 shutdown /s /t 29 /c
		$a_81_2 = {72 75 6e 64 6c 6c 33 32 20 75 73 65 72 33 32 2e 64 6c 6c 2c 4c 6f 63 6b 57 6f 72 6b 53 74 61 74 69 6f 6e } //1 rundll32 user32.dll,LockWorkStation
		$a_81_3 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //1 InternetConnectA
		$a_81_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d } //1 taskkill /f /im
		$a_81_5 = {33 66 62 64 30 34 66 35 2d 62 31 65 64 2d 34 30 36 30 2d 39 39 62 39 2d 66 63 61 37 66 66 35 39 63 31 31 33 } //1 3fbd04f5-b1ed-4060-99b9-fca7ff59c113
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}