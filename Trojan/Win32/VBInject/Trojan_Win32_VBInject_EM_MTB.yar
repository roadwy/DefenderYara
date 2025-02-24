
rule Trojan_Win32_VBInject_EM_MTB{
	meta:
		description = "Trojan:Win32/VBInject.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e } //1 schtasks /delete /tn
		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 77 69 6e 77 73 2e 65 78 65 } //1 taskkill /f /im winws.exe
		$a_81_2 = {43 6d 64 20 2f 78 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d } //1 Cmd /x/c taskkill /f /im
		$a_81_3 = {63 6d 64 20 2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 31 20 26 26 20 73 74 61 72 74 } //1 cmd /c timeout /t 1 && start
		$a_81_4 = {4c 61 75 6e 63 68 65 72 20 66 6f 72 20 5a 61 70 72 65 74 20 4e 65 77 5c 50 72 6f 6a 65 63 74 31 2e 76 62 70 } //1 Launcher for Zapret New\Project1.vbp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}