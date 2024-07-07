
rule Trojan_Win32_Startpage_MW{
	meta:
		description = "Trojan:Win32/Startpage.MW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 68 04 00 00 80 6a 00 68 90 01 04 68 01 03 00 80 6a 00 68 04 00 00 00 68 03 00 00 00 bb 90 01 04 e8 90 00 } //3
		$a_00_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 5c 31 34 30 30 } //1 \Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1400
		$a_01_2 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c } //1 Software\Microsoft\Internet Explorer\Main\
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 53 75 70 65 72 2d 45 43 5c } //1 Software\Super-EC\
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}