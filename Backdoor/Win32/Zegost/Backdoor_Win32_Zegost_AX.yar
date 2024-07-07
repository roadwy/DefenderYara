
rule Backdoor_Win32_Zegost_AX{
	meta:
		description = "Backdoor:Win32/Zegost.AX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {3e 6e 75 6c 20 64 65 6c 20 25 30 20 2f 73 2f 71 2f 61 2f 66 } //1 >nul del %0 /s/q/a/f
		$a_01_1 = {48 61 72 64 77 61 72 65 5c 44 65 73 63 72 69 70 74 69 6f 6e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //1 Hardware\Description\System\CentralProcessor\0
		$a_00_2 = {6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e } //1 microsoft\windows nt\currentversion\winlogon
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 64 25 73 } //1 http://%s:%d/%d%s
		$a_01_4 = {00 53 61 6b 65 72 45 76 65 6e 74 00 } //1 匀歡牥癅湥t
		$a_03_5 = {ff d6 50 ff d7 ff d0 68 7f 03 00 00 6a 00 68 90 01 03 10 90 02 06 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}