
rule Trojan_Win32_Startpage_PZ{
	meta:
		description = "Trojan:Win32/Startpage.PZ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 c9 8a 08 e3 08 80 f1 08 88 08 40 eb f4 } //2
		$a_01_1 = {77 69 6e 64 6f 77 73 5c 75 73 70 31 30 2e 64 6c } //1 windows\usp10.dl
		$a_01_2 = {5c 6e 70 72 6f 74 65 63 74 2e 73 79 73 } //1 \nprotect.sys
		$a_01_3 = {2d 73 65 74 75 72 6c } //1 -seturl
		$a_01_4 = {73 74 61 74 2e 70 68 70 3f 75 69 64 3d 76 65 67 61 7a 79 } //1 stat.php?uid=vegazy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}