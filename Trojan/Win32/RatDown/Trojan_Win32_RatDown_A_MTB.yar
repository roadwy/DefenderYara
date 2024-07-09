
rule Trojan_Win32_RatDown_A_MTB{
	meta:
		description = "Trojan:Win32/RatDown.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f [0-25] 2f 52 61 74 2e 65 78 65 } //1
		$a_03_1 = {68 74 74 70 3a 2f 2f [0-25] 2f 41 73 79 6e 63 43 6c 69 65 6e 74 2e 62 69 6e } //1
		$a_01_2 = {43 6f 75 6c 64 20 6e 6f 74 20 68 69 64 65 20 66 69 6c 65 3a } //1 Could not hide file:
		$a_01_3 = {43 6f 75 6c 64 20 6e 6f 74 20 73 65 74 20 66 69 6c 65 20 74 6f 20 73 79 73 74 65 6d 20 66 69 6c 65 3a } //1 Could not set file to system file:
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 Software\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c } //1 \Microsoft\Windows\Start Menu\Programs\Startup\
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}