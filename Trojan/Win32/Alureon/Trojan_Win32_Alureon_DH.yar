
rule Trojan_Win32_Alureon_DH{
	meta:
		description = "Trojan:Win32/Alureon.DH,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 68 38 73 72 74 } //1 Software\h8srt
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 2f 3f 67 64 3d 25 73 26 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 } //1 http://%s/?gd=%s&affid=%s&subid=%s
		$a_01_2 = {5b 50 41 4e 45 4c 5f 53 49 47 4e 5f 43 48 45 43 4b 5d } //1 [PANEL_SIGN_CHECK]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}