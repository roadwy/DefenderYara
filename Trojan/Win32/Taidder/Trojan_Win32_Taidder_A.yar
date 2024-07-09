
rule Trojan_Win32_Taidder_A{
	meta:
		description = "Trojan:Win32/Taidder.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 6a 73 6a 6d 8d 85 d8 fd ff ff 50 } //1
		$a_01_1 = {71 3d 25 63 26 69 64 3d 25 73 26 25 63 3d 25 73 26 25 63 3d 25 73 26 63 3d 25 73 26 6c 3d 25 73 26 74 3d 25 75 26 6c 69 70 3d 25 73 26 74 73 3d 25 73 } //1 q=%c&id=%s&%c=%s&%c=%s&c=%s&l=%s&t=%u&lip=%s&ts=%s
		$a_01_2 = {4d 63 41 66 65 65 20 46 72 61 6d 65 77 6f 72 6b 20 53 65 72 76 69 63 65 } //1 McAfee Framework Service
		$a_02_3 = {89 f0 40 c6 04 ?? ?? ?? ?? 00 ce 89 f0 83 c0 02 c6 04 ?? ?? ?? ?? 00 cc } //1
		$a_00_4 = {b9 1a 00 00 00 31 d2 f7 f1 89 d7 83 c7 20 81 f7 a1 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}