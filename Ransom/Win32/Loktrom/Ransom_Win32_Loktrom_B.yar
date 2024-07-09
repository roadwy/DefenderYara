
rule Ransom_Win32_Loktrom_B{
	meta:
		description = "Ransom:Win32/Loktrom.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 03 03 00 00 be ?? ?? 40 00 8d bd c8 f3 ff ff f3 a5 a4 c7 45 f8 ?? 00 00 00 c7 45 f0 00 00 00 00 e8 14 01 00 00 89 45 f4 c7 45 f0 00 00 00 00 eb 09 8b 4d f0 83 c1 01 89 4d f0 8b 55 f0 3b 55 f4 0f 8d d0 00 00 00 8b 45 f0 8a 8c 05 c8 f3 ff ff 88 4d fe 8b 55 f0 83 c2 01 89 55 dc 0f be 45 fe 8b 4d dc 33 4d f8 03 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_Loktrom_B_2{
	meta:
		description = "Ransom:Win32/Loktrom.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 6b 6f 4d 6f 54 4f 00 } //1
		$a_01_1 = {50 6c 69 71 70 61 79 5f 6d 6f 6e 65 78 79 } //1 Pliqpay_monexy
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /F /IM explorer.exe
		$a_00_3 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 6d 69 6e 69 6d 61 6c } //1 System\CurrentControlSet\Control\SafeBoot\minimal
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {61 6c 66 61 61 62 61 62 61 67 61 6c 61 6d 61 67 61 } //1 alfaababagalamaga
		$a_01_7 = {4b 4c 42 54 42 54 4e 42 49 54 42 54 4e 31 5f 42 49 54 4d 41 50 } //1 KLBTBTNBITBTN1_BITMAP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}
rule Ransom_Win32_Loktrom_B_3{
	meta:
		description = "Ransom:Win32/Loktrom.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 10 00 00 "
		
	strings :
		$a_03_0 = {8d 40 00 80 60 27 ef 84 d2 74 04 80 48 27 10 8b 48 1c e3 14 50 74 12 ff 15 ?? ?? ?? ?? 58 6a 05 ff 70 1c e8 } //1
		$a_01_1 = {66 c7 80 38 01 00 00 01 01 80 48 34 30 8b 90 ba 00 00 00 83 c2 16 89 90 c2 00 00 00 5a 50 e8 } //1
		$a_01_2 = {f0 e0 e2 e8 eb e0 ec 20 fd ea f1 ef eb f3 e0 f2 e0 f6 e8 e8 20 ce d1 20 57 69 6e 64 6f 77 73 2e } //1
		$a_01_3 = {cf f0 e8 eb ee e6 e5 ed e8 e5 ec 20 4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 72 69 74 79 20 45 73 73 65 6e 74 69 61 6c 73 } //1
		$a_01_4 = {25 43 46 25 46 30 25 45 38 25 45 42 25 45 45 25 45 36 25 45 35 25 45 44 25 45 38 25 45 35 25 45 43 2b 4d 69 63 72 6f 73 6f 66 74 2b 53 65 63 75 72 69 74 79 2b 45 73 73 65 6e 74 69 61 6c 73 } //1 %CF%F0%E8%EB%EE%E6%E5%ED%E8%E5%EC+Microsoft+Security+Essentials
		$a_01_5 = {25 45 41 25 45 45 25 46 30 25 45 46 25 45 45 25 46 30 25 45 30 25 46 36 25 45 38 25 45 38 2b 4d 69 63 72 6f 73 6f 66 74 25 32 45 } //1 %EA%EE%F0%EF%EE%F0%E0%F6%E8%E8+Microsoft%2E
		$a_01_6 = {ea ee f0 ef ee f0 e0 f6 e8 e8 20 4d 69 63 72 6f 73 6f 66 74 2e } //1
		$a_01_7 = {57 49 4e 44 4f 57 53 20 c7 c0 c1 cb ce ca c8 d0 ce c2 c0 cd } //1
		$a_01_8 = {ed e0 20 f1 f3 ec ec f3 20 35 30 30 20 f0 f3 e1 eb e5 e9 2e } //1
		$a_00_9 = {2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 } //1
		$a_01_10 = {f2 e5 f0 ec e8 ed e0 eb e0 20 e1 f3 e4 e5 f2 20 ed e0 ef e5 f7 e0 f2 e0 ed 20 ea ee e4 20 } //1
		$a_01_11 = {c2 e0 f8 20 ea ee ec ef fc fe f2 e5 f0 20 e7 e0 e1 eb ee ea e8 f0 ee e2 e0 ed 20 e7 e0 20 ef f0 ee f1 ec ee f2 f0 2c 20 ea ee ef e8 f0 ee e2 e0 ed e8 e5 } //1
		$a_03_12 = {75 68 6a 11 e8 ?? ?? ?? ?? 93 6a 12 e8 ?? ?? ?? ?? 09 d8 78 48 } //2
		$a_01_13 = {00 65 78 70 6b 69 6c 6c 3d } //1
		$a_01_14 = {c3 77 69 6e 64 6f 77 73 73 65 63 75 72 69 74 79 00 } //1
		$a_01_15 = {43 3a 5c 73 65 74 75 70 2e 72 6e 64 } //1 C:\setup.rnd
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_03_12  & 1)*2+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=6
 
}
rule Ransom_Win32_Loktrom_B_4{
	meta:
		description = "Ransom:Win32/Loktrom.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 43 3a 5c 57 49 4e 44 ce 57 53 5c e5 f5 f0 6c ee 72 e5 72 2e 65 78 65 00 } //1
		$a_01_1 = {00 4c 6f 6b 6f 4d 6f 54 4f 00 } //1 䰀歯䵯呯O
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}