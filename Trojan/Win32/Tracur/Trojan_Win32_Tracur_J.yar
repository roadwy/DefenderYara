
rule Trojan_Win32_Tracur_J{
	meta:
		description = "Trojan:Win32/Tracur.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 37 c7 45 70 20 4e 00 00 ff 15 ?? ?? ?? ?? 8b d8 3b de 74 6c } //2
		$a_01_1 = {25 73 3f 71 3d 25 73 26 73 75 3d 25 73 } //1 %s?q=%s&su=%s
		$a_01_2 = {75 3d 25 73 26 61 3d 25 73 26 69 3d 25 73 26 73 3d 25 73 } //1 u=%s&a=%s&i=%s&s=%s
		$a_01_3 = {25 73 3f 70 69 6e 67 3d 31 26 25 73 } //1 %s?ping=1&%s
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}