
rule Trojan_Win32_Zusy_KK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6a 01 6a 02 83 ec 0c 8b 44 24 14 83 c0 3c 8b 00 03 44 24 14 83 c0 78 85 c0 0f 84 aa 00 00 00 } //20
		$a_01_1 = {b6 12 00 d6 b6 12 00 e6 b6 12 00 fc b6 12 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Zusy_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a c3 f6 eb 32 45 13 8a cb c0 e1 02 32 ca 02 c1 00 44 1d f8 43 83 fb 08 } //20
		$a_01_1 = {8b 55 fc 30 0c 02 40 3b 45 0c } //10
		$a_01_2 = {70 63 6c 44 72 61 67 6f 76 2e 65 78 65 } //5 pclDragov.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win32_Zusy_KK_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8d 47 01 33 ca 2b ca 80 f9 ?? 0f 45 c7 46 8b f8 3b f5 } //20
		$a_03_1 = {8b c8 33 ca 2b ca 8b 54 24 10 80 f9 ?? 8d 42 01 0f 45 c2 8b c8 8b 44 24 0c 40 89 4c 24 10 89 44 24 0c 3b c7 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Zusy_KK_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 89 c2 c1 ea 1f 01 d0 d1 f8 89 c2 8b 45 08 01 d0 8b 4d f4 8b 55 f0 01 ca 0f b6 00 88 02 8b 45 f4 89 c2 c1 ea 1f 01 d0 d1 f8 89 c2 8b 45 08 01 d0 8b 55 f4 8d 4a 01 8b 55 f0 01 ca 0f b6 00 88 02 83 45 f4 01 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}
rule Trojan_Win32_Zusy_KK_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //20 get_Assembly
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //5 GetExecutingAssembly
		$a_01_2 = {24 32 64 63 31 63 33 62 38 2d 34 31 33 31 2d 34 37 35 35 2d 61 34 36 36 2d 39 61 30 65 63 64 34 65 34 34 65 38 } //3 $2dc1c3b8-4131-4755-a466-9a0ecd4e44e8
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3) >=28
 
}
rule Trojan_Win32_Zusy_KK_MTB_6{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 85 b0 fe ff ff 00 00 00 00 8d 85 f0 fe ff ff 89 44 24 0c 8d 85 b0 fe ff ff 89 44 24 08 8b 45 10 c7 85 f0 fe ff ff 00 00 00 00 89 44 24 04 8b 45 0c 89 04 24 } //20
		$a_01_1 = {c7 41 78 00 00 00 00 83 c1 08 c7 41 74 00 00 00 00 39 ce } //10
		$a_01_2 = {e8 5d 10 00 00 b9 35 00 00 00 31 d2 f7 f1 8a 44 15 b2 88 04 33 46 eb e3 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win32_Zusy_KK_MTB_7{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 05 00 00 "
		
	strings :
		$a_01_0 = {89 90 14 fb ff ff 4a 89 10 c7 80 ec 04 00 00 01 00 00 00 8b 98 d8 09 00 00 43 89 98 d4 09 00 00 83 e8 04 83 fa 01 } //20
		$a_81_1 = {72 65 67 2e 65 78 65 20 64 65 6c 65 74 65 20 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4e 65 74 77 6f 72 6b 5c 7b 34 44 33 36 45 39 36 37 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d 20 2f 66 } //10 reg.exe delete HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\{4D36E967-E325-11CE-BFC1-08002BE10318} /f
		$a_81_2 = {53 56 30 48 30 53 54 2e 45 58 45 } //3 SV0H0ST.EXE
		$a_81_3 = {49 45 58 50 31 4f 52 45 52 2e 45 58 45 } //2 IEXP1ORER.EXE
		$a_81_4 = {53 56 43 48 30 35 54 2e 45 58 45 } //1 SVCH05T.EXE
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*3+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=36
 
}
rule Trojan_Win32_Zusy_KK_MTB_8{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {25 32 36 5c 57 69 6e 64 6f 77 73 5c 64 72 69 76 65 72 2e 65 78 65 20 78 20 2d 72 20 2d 65 70 32 20 2d 68 70 6c 69 6d 70 69 64 32 39 30 33 33 39 32 20 40 24 } //2 %26\Windows\driver.exe x -r -ep2 -hplimpid2903392 @$
		$a_01_2 = {25 32 36 5c 57 69 6e 64 6f 77 73 5c 70 61 73 2e 72 61 72 20 62 6c 61 74 2e 65 78 65 20 40 24 } //3 %26\Windows\pas.rar blat.exe @$
		$a_01_3 = {25 32 36 5c 57 69 6e 64 6f 77 73 5c 70 61 73 2e 72 61 72 20 41 6e 79 44 65 73 6b 2e 65 78 65 20 40 24 } //4 %26\Windows\pas.rar AnyDesk.exe @$
		$a_01_4 = {25 32 36 5c 57 69 6e 64 6f 77 73 5c 66 69 6e 64 2e 63 6d 64 20 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 70 72 6f 66 69 6c 65 73 20 73 74 61 74 65 20 6f 66 66 } //5 %26\Windows\find.cmd netsh advfirewall set allprofiles state off
		$a_01_5 = {25 32 36 5c 57 69 6e 64 6f 77 73 5c 66 69 6e 64 2e 63 6d 64 20 73 63 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } //6 %26\Windows\find.cmd sc stop WinDefend
		$a_01_6 = {25 32 36 5c 57 69 6e 64 6f 77 73 5c 66 69 6e 64 2e 63 6d 64 20 73 63 20 64 65 6c 65 74 65 20 4d 70 73 53 76 63 } //7 %26\Windows\find.cmd sc delete MpsSvc
		$a_01_7 = {25 32 36 5c 57 69 6e 64 6f 77 73 5c 66 69 6e 64 2e 63 6d 64 20 41 6e 79 44 65 73 6b 2e 65 78 65 20 2d 2d 69 6e 73 74 61 6c 6c 20 40 24 } //8 %26\Windows\find.cmd AnyDesk.exe --install @$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5+(#a_01_5  & 1)*6+(#a_01_6  & 1)*7+(#a_01_7  & 1)*8) >=36
 
}