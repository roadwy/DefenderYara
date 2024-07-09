
rule Trojan_Win32_Lokibot_MFP_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {ff 75 08 ff 75 fc 58 59 90 01 c8 ff 30 90 90 59 90 91 34 c5 90 88 01 ff 45 fc 81 7d fc 78 5b 00 00 75 } //1
		$a_81_1 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 } //1 System\CurrentControlSet\Control\Keyboard Layouts\%.8x
		$a_81_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_81_3 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 41 } //1 MapVirtualKeyA
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Lokibot_MFP_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 4e 43 48 20 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 69 63 46 54 50 5c 46 54 50 41 63 63 6f 75 6e 74 73 } //1 Software\NCH Software\ClassicFTP\FTPAccounts
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 38 70 65 63 78 73 74 75 64 69 6f 73 5c 43 79 62 65 72 66 6f 78 38 36 } //1 SOFTWARE\8pecxstudios\Cyberfox86
		$a_81_2 = {44 6c 52 79 63 71 31 74 50 32 76 53 65 61 6f 67 6a 35 62 45 55 46 7a 51 69 48 54 39 64 6d 4b 43 6e 36 75 66 37 78 73 4f 59 30 68 70 77 72 34 33 56 49 4e 58 38 4a 47 42 41 6b 4c 4d 5a 57 } //1 DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW
		$a_81_3 = {55 32 58 70 65 6b 56 76 74 59 71 30 66 77 73 78 37 45 44 75 5a 6a 72 43 6f 39 47 63 46 31 42 36 48 6c 33 35 38 6d 62 7a 6e 79 4c 57 64 4d 41 4e 61 34 54 53 4b 4a 68 49 69 4f 50 67 51 52 } //1 U2XpekVvtYq0fwsx7EDuZjrCo9GcF1B6Hl358mbznyLWdMANa4TSKJhIiOPgQR
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Lokibot_MFP_MTB_3{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 06 00 00 "
		
	strings :
		$a_02_0 = {ff 95 c0 fd ff ff c7 85 ec fd ff ff ?? ?? ?? ?? eb 0f 8b 85 ec fd ff ff 83 c0 01 89 85 ec fd ff ff 8b 8d ec fd ff ff 3b 8d d8 fd ff ff 0f 83 37 01 00 00 8b 95 e4 fd ff ff 03 95 ec fd ff ff 8a 02 88 85 f3 fd ff ff 0f b6 8d f3 fd ff ff 83 e9 59 88 8d f3 fd ff ff 0f b6 95 f3 fd ff ff } //10
		$a_02_1 = {ff 95 c0 fd ff ff c7 85 ec fd ff ff ?? ?? ?? ?? eb 0f 8b 85 ec fd ff ff 83 c0 01 89 85 ec fd ff ff 8b 8d ec fd ff ff 3b 8d d8 fd ff ff 0f 83 ee ?? ?? ?? 8b 95 e4 fd ff ff 03 95 ec fd ff ff 8a 02 88 85 f3 fd ff ff 0f b6 8d f3 fd ff ff 03 8d ec fd ff ff 88 8d f3 fd ff ff 0f b6 95 f3 fd ff ff } //10
		$a_81_2 = {43 6c 6f 73 65 43 6c 69 70 62 6f 61 72 64 } //1 CloseClipboard
		$a_81_3 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_81_4 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //1 EmptyClipboard
		$a_81_5 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //1 OpenClipboard
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}
rule Trojan_Win32_Lokibot_MFP_MTB_4{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 8b 55 0c 83 c9 ff 56 8b 75 08 eb ?? 0f b6 06 4a 33 c8 46 6a 08 58 f6 c1 ?? 74 06 81 f1 54 ad 58 43 d1 e9 48 75 ?? 85 d2 75 ?? f7 d1 8b c1 } //10
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4e 43 48 20 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 69 63 46 54 50 5c 46 54 50 41 63 63 6f 75 6e 74 73 } //1 Software\NCH Software\ClassicFTP\FTPAccounts
		$a_81_2 = {53 4f 46 54 57 41 52 45 5c 38 70 65 63 78 73 74 75 64 69 6f 73 5c 43 79 62 65 72 66 6f 78 38 36 } //1 SOFTWARE\8pecxstudios\Cyberfox86
		$a_81_3 = {44 6c 52 79 63 71 31 74 50 32 76 53 65 61 6f 67 6a 35 62 45 55 46 7a 51 69 48 54 39 64 6d 4b 43 6e 36 75 66 37 78 73 4f 59 30 68 70 77 72 34 33 56 49 4e 58 38 4a 47 42 41 6b 4c 4d 5a 57 } //1 DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW
		$a_81_4 = {55 32 58 70 65 6b 56 76 74 59 71 30 66 77 73 78 37 45 44 75 5a 6a 72 43 6f 39 47 63 46 31 42 36 48 6c 33 35 38 6d 62 7a 6e 79 4c 57 64 4d 41 4e 61 34 54 53 4b 4a 68 49 69 4f 50 67 51 52 } //1 U2XpekVvtYq0fwsx7EDuZjrCo9GcF1B6Hl358mbznyLWdMANa4TSKJhIiOPgQR
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}
rule Trojan_Win32_Lokibot_MFP_MTB_5{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 17 5e 1b 03 24 e2 67 dd 4d a2 67 30 41 0c fd b1 55 51 89 8d b1 0c 22 5c c2 df 2c ab 98 f4 ed ee 89 ef a7 29 b0 5b 3c 8b e9 a7 9e 19 cb a0 a6 ce 73 76 e6 55 d6 34 08 fe 34 19 52 75 13 fe d4 7c af ef 1d 3b 92 04 d3 1d f3 69 6e 21 64 6c 1c 59 76 9c 27 6d ad 5f 09 b6 0c 36 7f b0 10 d4 95 e8 a6 06 e4 90 c7 99 09 75 91 80 7a 41 d2 41 18 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}