
rule Trojan_Win64_BypassUAC_NE_MTB{
	meta:
		description = "Trojan:Win64/BypassUAC.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4e 6c 73 5c 43 61 6c 65 6e 64 61 72 73 5c 4a 61 70 61 6e 65 73 65 5c 45 72 61 } //2 System\CurrentControlSet\Control\Nls\Calendars\Japanese\Era
		$a_81_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 } //2 C:\Windows\system32\WindowsPowerShell\v1.0\powershell.ex
		$a_81_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Ru
		$a_81_3 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d } //1 C:\windows\tem
		$a_81_4 = {24 64 69 73 61 62 6c 65 20 75 61 63 } //1 $disable uac
		$a_81_5 = {24 64 69 73 61 62 6c 65 20 72 65 67 65 64 69 74 } //1 $disable regedit
		$a_81_6 = {68 65 6e 74 61 69 } //1 hentai
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=10
 
}
rule Trojan_Win64_BypassUAC_NE_MTB_2{
	meta:
		description = "Trojan:Win64/BypassUAC.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-20] 5c 00 73 00 6f 00 75 00 72 00 63 00 65 00 5c 00 72 00 65 00 70 00 6f 00 73 00 5c 00 [0-50] 5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-50] 2e 00 70 00 64 00 62 00 } //3
		$a_02_1 = {43 3a 5c 55 73 65 72 73 5c [0-20] 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c [0-50] 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c [0-50] 2e 70 64 62 } //3
		$a_81_2 = {65 74 74 69 6e 67 73 5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 ettings\Shell\Open\command
		$a_81_3 = {61 74 65 45 78 65 63 75 74 65 } //1 ateExecute
		$a_81_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 66 6f 64 } //1 C:\Windows\System32\fod
		$a_81_5 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 } //1 cmd.exe /c start C:\Windows\System32\cmd.exe
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}