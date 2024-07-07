
rule Trojan_Win32_Farfli_MJ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {31 31 31 2e 63 66 35 39 39 2e 63 6f 6d } //1 111.cf599.com
		$a_80_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 65 78 70 6c 6f 72 2e 65 78 65 } //C:\WINDOWS\SYSTEM32\explor.exe  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_3 = {43 3a 5c 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 73 65 74 74 69 6e 67 73 5c 20 41 6c 6c 20 75 73 65 72 73 5c 73 74 61 72 74 20 6d 65 6e 75 5c 70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 20 75 70 5c 65 78 70 6c 6f 72 2e 65 78 65 } //C:\documents and settings\ All users\start menu\programs\start up\explor.exe  1
		$a_81_4 = {31 39 32 2e 31 36 38 2e 31 2e 32 34 34 } //1 192.168.1.244
		$a_81_5 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_81_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}