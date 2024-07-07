
rule Trojan_Win32_Zonsterarch_Q{
	meta:
		description = "Trojan:Win32/Zonsterarch.Q,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 61 00 73 00 74 00 2e 00 72 00 75 00 2f 00 65 00 78 00 65 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 } //1 http://downloadfast.ru/exe/index.php
		$a_01_1 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 66 00 69 00 6e 00 64 00 20 00 4d 00 79 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 20 00 6c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 } //1 Could not find MyDocuments folder location.
		$a_01_2 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 } //1 Select Folder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}