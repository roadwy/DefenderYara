
rule Trojan_Win32_Zusy_EC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 c0 10 2b c1 c1 e8 10 40 c3 33 c0 40 2b c6 2b c2 c3 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Zusy_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8b 55 14 80 3a 00 74 f8 90 90 90 90 ac 32 02 aa 90 90 90 90 42 49 85 c9 75 e9 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Zusy_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 4f 52 4b 5f 32 30 31 36 30 33 32 38 31 37 35 36 30 30 37 36 31 39 34 33 } //1 WORK_20160328175600761943
		$a_01_1 = {63 3a 5c 5c 44 65 73 74 72 6f } //1 c:\\Destro
		$a_81_2 = {6f 74 68 69 6e 66 } //1 othinf
		$a_81_3 = {4e 6b 47 79 56 69 41 4a 6b 77 48 69 4c 47 } //1 NkGyViAJkwHiLG
		$a_81_4 = {41 4a 6b 77 48 69 4c 47 59 } //1 AJkwHiLGY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zusy_EC_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {56 48 4a 70 59 57 77 67 63 47 56 79 61 57 39 6b 49 47 68 68 63 79 42 6c 65 48 42 70 63 6d 56 6b 4c 67 3d 3d } //1 VHJpYWwgcGVyaW9kIGhhcyBleHBpcmVkLg==
		$a_81_1 = {51 32 68 70 62 47 74 68 64 45 4a 31 62 6d 52 73 5a 51 3d 3d } //1 Q2hpbGthdEJ1bmRsZQ==
		$a_81_2 = {54 55 46 4a 54 41 3d 3d } //1 TUFJTA==
		$a_81_3 = {51 32 68 70 62 47 74 68 64 45 31 68 61 57 77 3d } //1 Q2hpbGthdE1haWw=
		$a_01_4 = {49 4e 4a 45 43 54 5f 45 4e 4a 4f 59 45 52 53 2e 70 64 62 } //1 INJECT_ENJOYERS.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zusy_EC_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {46 75 6e 46 75 6e 46 75 6e } //1 FunFunFun
		$a_81_1 = {73 68 61 6d 70 6c 65 2e 72 75 } //1 shample.ru
		$a_81_2 = {53 68 61 6d 70 6c 65 2e 70 64 62 } //1 Shample.pdb
		$a_81_3 = {47 65 74 54 65 6d 70 50 61 74 68 57 } //1 GetTempPathW
		$a_81_4 = {43 3a 5c 54 45 4d 50 5c 73 79 73 74 65 6d 2e 65 78 65 } //1 C:\TEMP\system.exe
		$a_81_5 = {43 3a 5c 54 45 4d 50 5c 53 48 41 4d 70 6c 65 2e 64 61 74 } //1 C:\TEMP\SHAMple.dat
		$a_81_6 = {53 6f 66 74 77 61 72 65 5c 53 48 41 4d 70 6c 65 } //1 Software\SHAMple
		$a_81_7 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Windows\CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}