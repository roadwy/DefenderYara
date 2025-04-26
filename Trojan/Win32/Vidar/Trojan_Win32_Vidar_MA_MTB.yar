
rule Trojan_Win32_Vidar_MA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 06 89 45 fc 33 d2 8b c3 6a ?? 59 f7 f1 8b 4d fc 8a 04 0a 8b 4d 0c 30 04 1f 43 8b 41 04 8b 39 2b c7 3b d8 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 69 d2 fd 43 03 00 81 c2 c3 9e 26 00 89 15 14 ?? 45 00 8a 0d 16 ?? 45 00 30 0c 30 83 ff 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 28 89 44 24 20 8b 44 24 24 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 14 8b 4c 24 2c 8d 44 24 14 c7 05 24 0f 4d 00 ee 3d ea f4 e8 ?? ff ff ff 8b 44 24 20 31 44 24 10 8b 54 24 10 31 54 24 14 81 3d 2c 0f 4d 00 13 02 00 00 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Vidar_MA_MTB_4{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b 45 0c 8d 48 01 8a 10 40 84 d2 75 ?? 2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 55 08 32 04 0a 46 88 01 3b 75 10 72 } //10
		$a_01_2 = {5c 57 61 6c 6c 65 74 73 5c } //2 \Wallets\
		$a_01_3 = {5c 54 65 6c 65 67 72 61 6d 5c } //2 \Telegram\
		$a_01_4 = {20 2f 66 20 26 20 74 69 6d 65 6f 75 74 20 2f 74 20 36 20 26 20 64 65 6c 20 2f 66 20 2f 71 } //2  /f & timeout /t 6 & del /f /q
		$a_01_5 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //2 /c taskkill /im
		$a_01_6 = {5c 73 63 72 65 65 6e 73 68 6f 74 2e 6a 70 67 } //2 \screenshot.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=21
 
}
rule Trojan_Win32_Vidar_MA_MTB_5{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 77 9d 6e 61 8f cb b8 15 dc fc d3 47 0f 2e 62 1b 7d 6a bf 25 8d 84 f0 a9 f3 cb 82 15 70 13 2b } //2
		$a_01_1 = {16 a5 10 90 12 f3 c8 7d f6 0c 92 67 ff ff ff ff d9 bb d0 4d db da 77 45 e4 e9 e2 d4 b5 b6 c7 19 } //2
		$a_01_2 = {85 5c 6a 56 1c 88 8e b0 1e 6d e2 7c af 7f e5 5a 74 2a 70 7d 95 9b f0 7a 70 14 4c 8f 28 3e a3 60 ea 61 55 bb 9f f0 cf 5b 73 a5 95 e2 54 e5 5c 0f a4 fa a3 5a ea 21 b9 12 a5 50 04 13 cb 98 } //2
		$a_01_3 = {e0 00 02 01 0b 01 0a 00 00 d4 03 00 00 30 19 00 00 00 00 00 4f 06 25 } //2
		$a_01_4 = {2e 76 6d 70 30 } //1 .vmp0
		$a_01_5 = {2e 76 6d 70 32 } //1 .vmp2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}