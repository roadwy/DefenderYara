
rule Trojan_Win32_Dogrobot_G_dll{
	meta:
		description = "Trojan:Win32/Dogrobot.G!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3c e9 75 0b a1 01 90 01 03 8d 90 01 01 05 90 01 03 8b 0f 33 c0 81 f9 90 01 04 74 90 00 } //2
		$a_00_1 = {8b 44 24 1c 8b 0e 3b c8 75 10 8b 4c 24 20 55 51 56 ff 15 } //1
		$a_03_2 = {6a 05 6a 18 8d 45 90 01 01 50 8d 4d 90 01 01 51 8b 55 90 01 01 52 b8 90 01 03 86 ff d0 90 00 } //1
		$a_00_3 = {25 63 3a 5c 50 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 4d 53 44 4e } //1 %c:\Program files\MSDN
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}