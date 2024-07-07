
rule TrojanDownloader_Win32_Malushka_T{
	meta:
		description = "TrojanDownloader:Win32/Malushka.T,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 63 75 6d 65 6e 74 2e 62 6f 74 67 6f 77 61 79 2e 73 75 62 6d 69 74 28 29 } //10 document.botgoway.submit()
		$a_01_1 = {3c 72 65 66 65 72 65 72 3e 2a 3c 2f 72 65 66 65 72 65 72 3e } //10 <referer>*</referer>
		$a_01_2 = {48 54 54 50 55 4c 54 49 4d 41 4c 49 4e 4b 3a } //10 HTTPULTIMALINK:
		$a_01_3 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 } //10 Connection: Keep-Alive
		$a_01_4 = {25 33 44 30 26 73 74 63 26 75 72 6c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 } //1 %3D0&stc&url=http://www.goog
		$a_01_5 = {2f 63 6c 69 63 6b 5f 73 65 63 6f 6e 64 5f 6e 65 77 33 2e 70 68 70 } //1 /click_second_new3.php
		$a_01_6 = {65 73 63 61 70 65 28 77 69 6e 64 6f 77 2e 6c 6f 63 61 74 69 6f 6e 2e 68 72 65 66 29 } //1 escape(window.location.href)
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=42
 
}