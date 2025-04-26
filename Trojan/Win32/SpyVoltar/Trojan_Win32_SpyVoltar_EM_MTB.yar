
rule Trojan_Win32_SpyVoltar_EM_MTB{
	meta:
		description = "Trojan:Win32/SpyVoltar.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 67 62 64 77 70 62 6d 2e 64 6c 6c } //1 C:\WINDOWS\system32\gbdwpbm.dll
		$a_81_1 = {62 65 67 75 6e 2e 72 75 2f 63 6c 69 63 6b 2e 6a 73 70 3f 75 72 6c 3d } //1 begun.ru/click.jsp?url=
		$a_81_2 = {5f 62 6c 61 6e 6b } //1 _blank
		$a_81_3 = {6f 77 35 64 69 72 61 73 75 65 6b 2e 63 6f 6d } //1 ow5dirasuek.com
		$a_81_4 = {6d 6b 6b 75 65 69 34 6b 64 73 7a 2e 63 6f 6d } //1 mkkuei4kdsz.com
		$a_81_5 = {6c 6f 75 73 74 61 2e 6e 65 74 } //1 lousta.net
		$a_81_6 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 6f 6d 73 65 63 6f 72 2e 65 78 65 } //1 %SystemRoot%\System32\omsecor.exe
		$a_81_7 = {25 41 50 50 44 41 54 41 25 5c 6f 6d 73 65 63 6f 72 2e 65 78 65 } //1 %APPDATA%\omsecor.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}