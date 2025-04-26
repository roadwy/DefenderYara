
rule TrojanClicker_Win32_VB_JT{
	meta:
		description = "TrojanClicker:Win32/VB.JT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 61 00 74 00 61 00 31 00 2e 00 79 00 6f 00 6f 00 75 00 38 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 http://data1.yoou8.com/
		$a_00_1 = {5c 00 41 00 44 00 3a 00 5c 00 77 00 6f 00 72 00 6b 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 5c 00 41 6d cf 91 0b 7a 8f 5e 32 00 5c 00 41 6d cf 91 0b 7a 8f 5e 5c 00 69 00 65 00 2e 00 76 00 62 00 70 00 } //1
		$a_01_2 = {64 00 6f 00 75 00 62 00 6c 00 65 00 63 00 6c 00 69 00 63 00 6b 00 } //1 doubleclick
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}