
rule Trojan_Win32_Startpage_JP{
	meta:
		description = "Trojan:Win32/Startpage.JP,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 7b 38 37 31 43 35 33 38 30 2d 34 32 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d 5c 73 68 65 6c 6c 5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 5c 43 6f 6d 6d 61 6e 64 } //1 CLSID\{871C5380-42A0-1069-A2EA-08002B30309D}\shell\OpenHomePage\Command
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //1 Microsoft\Internet Explorer\Quick Launch
		$a_01_2 = {47 75 57 53 2e 52 75 6e } //1 GuWS.Run
		$a_01_3 = {76 62 68 69 64 65 } //1 vbhide
		$a_01_4 = {33 36 30 73 65 } //1 360se
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}