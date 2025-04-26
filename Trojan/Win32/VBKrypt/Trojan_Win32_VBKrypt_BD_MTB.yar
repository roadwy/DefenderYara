
rule Trojan_Win32_VBKrypt_BD_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 57 6f 72 64 2e 47 72 61 62 62 65 72 } //1 WinWord.Grabber
		$a_01_1 = {67 72 61 62 44 6f 63 } //1 grabDoc
		$a_01_2 = {44 00 6f 00 77 00 6e 00 65 00 78 00 65 00 63 00 } //1 Downexec
		$a_01_3 = {61 00 76 00 67 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 avgnt.exe
		$a_01_4 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 43 00 4f 00 4d 00 4f 00 44 00 4f 00 } //1 Program Files\COMODO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}