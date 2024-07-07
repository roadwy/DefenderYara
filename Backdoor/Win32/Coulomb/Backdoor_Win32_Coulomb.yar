
rule Backdoor_Win32_Coulomb{
	meta:
		description = "Backdoor:Win32/Coulomb,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 6c 6f 61 64 2e 69 70 62 69 6c 6c 2e 63 6f 6d } //2 dload.ipbill.com
		$a_01_1 = {47 45 54 20 2f 65 78 69 74 20 48 54 54 50 2f 31 2e 30 } //2 GET /exit HTTP/1.0
		$a_01_2 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 38 30 38 31 2f 64 69 61 6c 2e 68 74 6d 6c 3f } //2 http://127.0.0.1:8081/dial.html?
		$a_01_3 = {47 65 6f 54 61 72 67 65 74 74 69 6e 67 } //2 GeoTargetting
		$a_01_4 = {44 69 61 6c 6c 65 72 43 6c 61 73 73 } //2 DiallerClass
		$a_01_5 = {2f 64 6c 72 64 69 72 2e 68 74 6d 6c } //2 /dlrdir.html
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=10
 
}
rule Backdoor_Win32_Coulomb_2{
	meta:
		description = "Backdoor:Win32/Coulomb,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 43 6f 75 6c 6f 6d 62 } //2 Software\Coulomb
		$a_01_1 = {2f 64 65 6c 2f 64 6c 72 64 69 72 2e 68 74 6d 6c 3f 44 69 61 6c 6c 65 72 49 50 3d 25 73 26 64 69 61 6c 6c 65 64 3d 25 73 26 73 69 74 65 3d 25 73 26 64 69 64 3d 25 73 26 75 64 61 74 61 3d 25 73 26 63 6f 75 6e 74 72 79 3d 25 } //3 /del/dlrdir.html?DiallerIP=%s&dialled=%s&site=%s&did=%s&udata=%s&country=%
		$a_01_2 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 38 30 38 39 2f 69 6e 64 65 78 2e 68 74 6d 6c 3f } //3 http://127.0.0.1:8089/index.html?
		$a_01_3 = {44 69 61 6c 6c 65 72 43 6c 61 73 73 } //1 DiallerClass
		$a_01_4 = {65 78 69 74 70 70 2e 68 74 6d 6c } //1 exitpp.html
		$a_01_5 = {63 63 61 72 64 2e 69 70 62 69 6c 6c 2e 63 6f 6d } //1 ccard.ipbill.com
		$a_01_6 = {47 45 54 20 2f 65 78 69 74 20 48 54 54 50 2f 31 2e 30 } //1 GET /exit HTTP/1.0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}
rule Backdoor_Win32_Coulomb_3{
	meta:
		description = "Backdoor:Win32/Coulomb,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 43 6f 75 6c 6f 6d 62 } //2 Software\Coulomb
		$a_01_1 = {2f 64 65 6c 2f 64 6c 72 64 69 72 2e 68 74 6d 6c 3f 44 69 61 6c 6c 65 72 49 50 3d 25 73 26 64 69 61 6c 6c 65 64 3d 25 73 26 73 69 74 65 3d 25 73 26 64 69 64 3d 25 73 26 75 64 61 74 61 3d 25 73 26 63 6f 75 6e 74 72 79 3d 25 } //3 /del/dlrdir.html?DiallerIP=%s&dialled=%s&site=%s&did=%s&udata=%s&country=%
		$a_01_2 = {49 6e 63 6f 72 72 65 63 74 20 50 49 4e 20 65 6e 74 65 72 65 64 } //1 Incorrect PIN entered
		$a_01_3 = {45 2d 6d 61 69 6c 20 61 64 64 72 65 73 73 65 73 20 64 6f 6e 27 74 20 6d 61 74 63 68 20 2d 20 70 6c 65 61 73 65 20 63 68 65 63 6b 20 61 6e 64 20 63 6f 72 72 65 63 74 } //2 E-mail addresses don't match - please check and correct
		$a_01_4 = {43 6f 75 6c 6f 6d 62 20 42 72 6f 77 73 65 72 57 57 57 } //2 Coulomb BrowserWWW
		$a_01_5 = {41 54 4c 42 52 4f 57 53 45 52 4c 69 62 57 57 57 } //1 ATLBROWSERLibWWW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=8
 
}