
rule Trojan_Win32_Wuprad_A{
	meta:
		description = "Trojan:Win32/Wuprad.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {7a 76 65 72 79 75 67 61 2e 63 6f 6d 2e 75 61 } //2 zveryuga.com.ua
		$a_01_1 = {64 6f 77 6e 63 6f 6e 74 72 6f 6c 6c 65 72 2f 3f 61 66 66 69 64 3d 25 73 } //2 downcontroller/?affid=%s
		$a_01_2 = {64 6f 77 6e 63 6f 6e 74 72 6f 6c 6c 65 72 2f 6d 61 72 6b 2e 70 68 70 } //2 downcontroller/mark.php
		$a_01_3 = {64 6f 77 6e 73 00 00 00 ff ff ff ff 01 00 00 00 3b 00 00 00 6d 61 73 74 00 } //1
		$a_03_4 = {00 c2 cd c8 cc c0 cd c8 c5 21 20 c2 fb 90 09 03 00 44 00 } //2
		$a_03_5 = {6a 21 57 6a 01 53 68 ?? ?? ?? ?? 51 ff d6 } //1
		$a_01_6 = {83 f8 02 74 44 8b 04 24 8d 4c 24 04 51 8d 54 24 0c 52 6a 00 6a 00 } //1
		$a_03_7 = {75 34 6a 00 8d 45 fc 50 68 90 09 0a 00 74 05 83 e8 04 8b 00 83 f8 20 } //1
		$a_03_8 = {ff d6 3d fd 2e 00 00 0f 84 ?? ?? ?? ?? ff d6 3d e7 2e 00 00 0f 84 ?? ?? ?? ?? 6a 31 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1) >=5
 
}