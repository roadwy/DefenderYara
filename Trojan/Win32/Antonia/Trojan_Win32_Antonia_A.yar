
rule Trojan_Win32_Antonia_A{
	meta:
		description = "Trojan:Win32/Antonia.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 72 65 67 75 70 64 61 74 65 73 2e 65 75 } //1 checkregupdates.eu
		$a_01_1 = {76 3d 25 64 26 75 3d 25 73 26 63 3d 25 64 26 66 3d 25 64 26 61 3d 25 64 26 64 3d 25 64 } //1 v=%d&u=%s&c=%d&f=%d&a=%d&d=%d
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 44 00 65 00 66 00 65 00 6e 00 64 00 72 00 76 00 50 00 72 00 6f 00 } //1 Software\DefendrvPro
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 41 6e 74 6f 6e 5c 44 6f 63 75 6d 65 6e 74 73 5c } //1 C:\Users\Anton\Documents\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}