
rule Trojan_Win32_Startpage_ME{
	meta:
		description = "Trojan:Win32/Startpage.ME,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 61 69 6e 22 20 2f 76 20 22 53 74 61 72 74 20 50 61 67 65 22 20 2f 64 20 68 74 74 70 3a 2f 2f 63 62 61 64 65 6e 6f 63 68 65 2e 63 6f 6d 20 2f 66 } //1 \Main" /v "Start Page" /d http://cbadenoche.com /f
		$a_01_1 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 22 2c 20 22 68 74 74 70 3a 2f 2f 63 62 61 64 65 6e 6f 63 68 65 2e 63 6f 6d 22 29 3b } //1 user_pref("browser.startup.homepage", "http://cbadenoche.com");
		$a_01_2 = {64 65 6c 20 70 72 6f 66 69 6c 65 2e 74 78 74 } //1 del profile.txt
		$a_01_3 = {66 6f 72 20 2f 66 20 25 25 61 20 69 6e 20 28 25 74 78 74 25 29 20 64 6f 20 73 65 74 20 6e 3d 25 25 61 } //1 for /f %%a in (%txt%) do set n=%%a
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}