
rule Trojan_Win32_Jaik_NH_MTB{
	meta:
		description = "Trojan:Win32/Jaik.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 77 77 2e 70 68 70 } //2 wwwww.php
		$a_01_1 = {65 00 78 00 65 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 5c 00 68 00 74 00 74 00 70 00 } //1 exepayload\http
		$a_02_2 = {54 45 4d 50 [0-04] 2e 74 78 74 } //1
		$a_01_3 = {6d 73 73 6c 61 63 2e 64 6c 6c } //1 msslac.dll
		$a_01_4 = {49 4e 54 45 52 4e 45 54 5f 4f 50 54 49 4f 4e 5f 50 41 53 53 57 4f 52 44 } //1 INTERNET_OPTION_PASSWORD
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_Win32_Jaik_NH_MTB_2{
	meta:
		description = "Trojan:Win32/Jaik.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {85 f6 75 15 e8 91 f4 ff ff c7 00 ?? 00 00 00 e8 ac f3 ff ff 83 c8 ff eb 3c 8b 46 0c } //2
		$a_01_1 = {61 67 65 6e 74 } //1 agent
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 20 30 } //1 shutdown /r /t 0
		$a_01_3 = {44 65 66 69 6e 65 63 2e 65 78 65 } //1 Definec.exe
		$a_01_4 = {6d 73 73 6c 61 63 2e 64 6c 6c } //1 msslac.dll
		$a_01_5 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 63 62 61 73 2e 6c 6e 6b } //1 AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\cbas.lnk
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}