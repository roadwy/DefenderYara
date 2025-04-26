
rule Trojan_Win32_Capface_B{
	meta:
		description = "Trojan:Win32/Capface.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 50 6f 73 74 4d 58 } //2 WinPostMX
		$a_01_1 = {45 6e 61 62 6c 65 46 69 72 65 77 61 6c 6c } //1 EnableFirewall
		$a_01_2 = {69 6d 67 25 64 5f 25 64 2e 6a 70 67 } //1 img%d_%d.jpg
		$a_01_3 = {6e 65 77 61 63 63 6f 75 6e 74 63 61 70 74 63 68 61 } //1 newaccountcaptcha
		$a_00_4 = {3c 00 69 00 66 00 72 00 61 00 6d 00 65 00 20 00 73 00 72 00 63 00 3d 00 27 00 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 74 00 6f 00 70 00 2e 00 6c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3d 00 22 00 68 00 74 00 } //1 <iframe src='javascript:top.location="ht
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}