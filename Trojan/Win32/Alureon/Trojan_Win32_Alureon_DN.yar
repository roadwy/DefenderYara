
rule Trojan_Win32_Alureon_DN{
	meta:
		description = "Trojan:Win32/Alureon.DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {76 0f 8a d0 80 c2 ?? 30 14 30 83 c0 01 3b c1 72 f1 } //2
		$a_03_1 = {76 11 8d 9b 00 00 00 00 80 34 18 ?? 83 c0 01 3b c6 72 f5 } //1
		$a_03_2 = {75 0e 83 c6 04 81 fe ?? ?? ?? ?? 72 e7 } //1
		$a_03_3 = {6a 40 6a 01 ff d6 50 6a 00 ff d6 8b 4c 24 ?? 50 6a 00 6a 00 } //1
		$a_01_4 = {5b 50 41 4e 45 4c 5f 53 49 47 4e 5f 43 48 45 43 4b 5d } //1 [PANEL_SIGN_CHECK]
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}