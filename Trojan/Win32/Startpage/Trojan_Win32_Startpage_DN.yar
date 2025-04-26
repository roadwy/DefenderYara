
rule Trojan_Win32_Startpage_DN{
	meta:
		description = "Trojan:Win32/Startpage.DN,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 61 66 66 63 67 69 2f 6f 6e 6c 69 6e 65 2e 66 63 67 69 3f 25 } //1 /affcgi/online.fcgi?%
		$a_01_1 = {2f 61 66 66 69 6c 69 61 74 65 2f 69 6e 74 65 72 66 61 63 65 33 2e 70 68 70 3f 75 73 65 72 69 64 3d } //1 /affiliate/interface3.php?userid=
		$a_01_2 = {68 74 74 70 3a 2f 2f 00 2f 78 78 6d 6d 32 2e 65 78 65 } //1 瑨灴⼺/砯浸㉭攮數
		$a_01_3 = {66 75 63 6b 20 6f 66 66 2c 20 62 75 64 64 79 00 53 6f 66 74 77 61 72 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}