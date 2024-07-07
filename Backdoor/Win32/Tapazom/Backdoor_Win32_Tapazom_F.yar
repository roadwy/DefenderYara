
rule Backdoor_Win32_Tapazom_F{
	meta:
		description = "Backdoor:Win32/Tapazom.F,SIGNATURE_TYPE_PEHSTR_EXT,40 01 ffffffdc 00 06 00 00 "
		
	strings :
		$a_01_0 = {eb 60 83 7d ec ff 75 0a 83 7d e8 ff 75 04 b3 01 eb 60 80 7d f7 0e 74 5a 80 7d f7 0a 74 22 80 7d f7 0d 74 1c } //100
		$a_03_1 = {8a 03 33 d2 8a d0 25 ff 00 00 00 d1 e8 2b d0 33 c0 8a 44 13 01 a3 90 01 02 40 00 33 c0 8a 03 33 d2 8a 13 d1 ea 2b c2 0f b6 04 03 90 00 } //100
		$a_01_2 = {6d 6d 7a 6f 2e 64 79 6e 64 6e 73 2e 6f 72 67 3a 31 31 34 33 } //50 mmzo.dyndns.org:1143
		$a_01_3 = {0b 49 6e 63 6c 6f 75 64 2e 65 78 65 } //50 䤋据潬摵攮數
		$a_01_4 = {48 49 44 2d 44 65 76 69 63 65 } //20 HID-Device
		$a_01_5 = {6d 7a 73 72 36 34 2e 64 6c 6c } //20 mzsr64.dll
	condition:
		((#a_01_0  & 1)*100+(#a_03_1  & 1)*100+(#a_01_2  & 1)*50+(#a_01_3  & 1)*50+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20) >=220
 
}