
rule Trojan_Win32_Startpage_IP{
	meta:
		description = "Trojan:Win32/Startpage.IP,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f } //1 C:\Program Files\Internet Explorer\iexplore.exe http://
		$a_01_1 = {7d 5c 73 68 65 6c 6c 5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 5c 43 6f 6d 6d 61 6e 64 5c } //1 }\shell\OpenHomePage\Command\
		$a_01_2 = {49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 } //1 InternetShortcut
		$a_01_3 = {24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 } //1 $$\wininit.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}