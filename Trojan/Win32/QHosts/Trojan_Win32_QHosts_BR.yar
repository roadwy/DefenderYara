
rule Trojan_Win32_QHosts_BR{
	meta:
		description = "Trojan:Win32/QHosts.BR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 32 37 2e 30 2e 30 2e 31 20 20 20 20 20 20 20 77 77 77 2e 69 6a 69 6e 73 68 61 6e 2e 63 6f 6d } //5 127.0.0.1       www.ijinshan.com
		$a_01_1 = {31 32 37 2e 30 2e 30 2e 31 20 20 20 20 20 20 20 6b 61 62 61 33 36 35 2e 63 6f 6d } //5 127.0.0.1       kaba365.com
		$a_00_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 51 00 51 00 45 00 78 00 74 00 72 00 65 00 6e 00 61 00 6c 00 2e 00 65 00 78 00 65 00 } //1 cmd /c taskkill /f /im QQExtrenal.exe
		$a_00_3 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //1 C:\WINDOWS\system32\drivers\etc\hosts
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}