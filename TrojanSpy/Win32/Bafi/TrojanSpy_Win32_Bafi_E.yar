
rule TrojanSpy_Win32_Bafi_E{
	meta:
		description = "TrojanSpy:Win32/Bafi.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00 } //1
		$a_00_1 = {74 00 70 00 61 00 63 00 5f 00 25 00 64 00 2e 00 6d 00 76 00 74 00 } //1 tpac_%d.mvt
		$a_00_2 = {56 6b 65 79 47 72 61 62 62 65 72 57 } //1 VkeyGrabberW
		$a_01_3 = {4d 00 6f 00 64 00 75 00 6c 00 65 00 5f 00 52 00 61 00 77 00 } //1 Module_Raw
		$a_01_4 = {73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 } //1 showpopup
		$a_00_5 = {41 00 64 00 6f 00 62 00 65 00 20 00 50 00 44 00 46 00 20 00 52 00 65 00 61 00 64 00 65 00 72 00 20 00 4c 00 69 00 6e 00 6b 00 20 00 48 00 65 00 6c 00 70 00 65 00 72 00 } //1 Adobe PDF Reader Link Helper
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}
rule TrojanSpy_Win32_Bafi_E_2{
	meta:
		description = "TrojanSpy:Win32/Bafi.E,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 64 00 75 00 6c 00 65 00 5f 00 52 00 61 00 77 00 } //1 Module_Raw
		$a_01_1 = {73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 } //1 showpopup
		$a_01_2 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00 } //1
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6c 00 69 00 6e 00 6b 00 72 00 64 00 72 00 2e 00 41 00 49 00 45 00 62 00 68 00 6f 00 } //1 Software\Classes\linkrdr.AIEbho
		$a_02_4 = {40 25 0f 00 00 80 79 90 01 01 48 83 c8 f0 40 8b 16 88 45 ff 8a 44 39 02 32 c3 88 04 11 8a 5c 39 02 41 3b 90 01 02 7c 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*10) >=13
 
}
rule TrojanSpy_Win32_Bafi_E_3{
	meta:
		description = "TrojanSpy:Win32/Bafi.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {c6 45 fc 06 68 90 01 04 8d 8d c0 fe ff ff e8 90 01 04 c6 45 fc 0a 68 90 01 04 8d 95 c0 fe ff ff 52 8d 85 9c fe ff ff 50 e8 90 01 04 83 c4 0c 89 85 38 fe ff ff 8b 8d 38 fe ff ff 89 8d 34 fe ff ff c6 45 fc 0b 68 90 01 04 8b 95 34 fe ff ff 52 90 00 } //1
		$a_01_1 = {0f b6 4d ff 03 c8 88 4d ff 0f b6 55 fe 83 c2 01 81 e2 0f 00 00 80 79 05 4a 83 ca f0 42 88 55 fe 8b 45 08 03 45 f0 0f b6 08 0f b6 55 ff 33 ca 8b 45 e8 8b 10 8b 45 f0 88 0c 02 8b 4d 08 03 4d f0 8a 11 88 55 ff eb 9d } //1
		$a_00_2 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 } //1 \CurrentVersion\Explorer\Browser Helper Objects\
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 6c 6f 67 69 6e 2e 70 68 70 } //1 https://www.facebook.com/login.php
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}