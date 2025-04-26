
rule Trojan_Win32_Startpage_AGL{
	meta:
		description = "Trojan:Win32/Startpage.AGL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 22 2c 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 6f 6b 67 65 6e 2e 63 6f 6d 2f 3f 72 65 66 3d 6d 73 22 29 3b } //1 user_pref("browser.startup.homepage", "http://www.okgen.com/?ref=ms");
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 61 6c 77 61 72 65 2e 63 6f 6d 00 } //1
		$a_01_2 = {25 73 5c 72 65 70 61 69 72 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}