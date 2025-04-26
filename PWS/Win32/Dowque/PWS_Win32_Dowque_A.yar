
rule PWS_Win32_Dowque_A{
	meta:
		description = "PWS:Win32/Dowque.A,SIGNATURE_TYPE_PEHSTR,09 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6d 2f 69 70 2f 69 70 2e 70 68 70 } //2 .com/ip/ip.php
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 54 65 6e 63 65 6e 74 5c 48 6f 6f 6b } //2 Software\Tencent\Hook
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_01_3 = {4e 75 6d 62 65 72 3d } //1 Number=
		$a_01_4 = {26 50 61 73 73 57 6f 72 64 3d } //2 &PassWord=
		$a_01_5 = {78 78 6b 78 78 78 78 6a 74 72 } //1 xxkxxxxjtr
		$a_01_6 = {79 79 79 72 74 38 6a 6a 6a } //1 yyyrt8jjj
		$a_01_7 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 SetWindowsHookEx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}