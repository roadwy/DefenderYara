
rule Trojan_Win32_Alureon_BJ{
	meta:
		description = "Trojan:Win32/Alureon.BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 10 8a d1 02 54 24 08 30 14 01 41 3b 4c 24 04 72 f0 } //2
		$a_03_1 = {75 f6 8d 45 08 50 68 13 01 00 00 90 09 22 00 c6 85 ?? ?? ?? ?? e9 } //2
		$a_01_2 = {68 44 44 41 4d 68 58 4b 4e 53 } //2 hDDAMhXKNS
		$a_01_3 = {6a 73 2e 70 68 70 3f 75 3d 25 73 } //1 js.php?u=%s
		$a_01_4 = {6b 65 79 77 6f 72 64 20 3d 20 52 65 67 45 78 70 2e 24 31 3b } //1 keyword = RegExp.$1;
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}