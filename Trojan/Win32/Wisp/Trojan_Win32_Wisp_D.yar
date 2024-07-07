
rule Trojan_Win32_Wisp_D{
	meta:
		description = "Trojan:Win32/Wisp.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 76 6f 73 74 69 6d 69 72 2e 63 6f 6d } //1 novostimir.com
		$a_01_1 = {5f 6e 6f 74 69 66 79 2e 65 78 65 00 66 72 77 6c 5f 73 65 74 2e 65 78 65 } //1
		$a_01_2 = {64 72 77 65 62 00 00 00 6e 6f 6e 6f 6e 6f } //1
		$a_01_3 = {6f 75 74 6c 6f 6f 6b 2e 65 78 65 00 65 69 70 78 6f 6c 65 72 65 2e 65 78 } //1
		$a_01_4 = {69 66 65 72 6f 66 2e 78 78 65 00 00 63 68 72 6f 6d 65 2e 65 78 65 } //1
		$a_01_5 = {63 6d 64 20 2f 63 20 22 72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 20 73 74 61 72 74 20 2f 74 20 52 45 47 5f 53 5a } //1 cmd /c "reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v start /t REG_SZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}