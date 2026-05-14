
rule Trojan_Win32_Zusy_ARR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_81_0 = {41 21 6c 40 6c 24 43 21 6c 5e 69 23 63 25 6b } //20 A!l@l$C!l^i#c%k
	condition:
		((#a_81_0  & 1)*20) >=20
 
}
rule Trojan_Win32_Zusy_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 0f af 06 83 c0 ?? 8b cb 50 6a } //7
		$a_01_1 = {0f af d0 03 d7 89 14 81 8b 0e 40 3b c1 } //13
	condition:
		((#a_03_0  & 1)*7+(#a_01_1  & 1)*13) >=20
 
}
rule Trojan_Win32_Zusy_ARR_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {87 2c 24 5c 89 14 24 57 89 0c 24 8b 14 24 83 ec } //10
		$a_01_1 = {47 30 16 b0 83 41 5d } //7
		$a_03_2 = {ab 3b cd 5b c7 30 dd 65 c0 72 ?? ?? 4c 11 b4 59 } //3
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*7+(#a_03_2  & 1)*3) >=20
 
}
rule Trojan_Win32_Zusy_ARR_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 43 da 33 06 4d 6c 3c 45 } //15
		$a_03_1 = {dc 36 02 ec 98 6b c1 ?? ee d3 ce 32 4a fc } //5
		$a_01_2 = {33 3c 24 31 3c 24 33 3c 24 5c 8d 44 24 24 } //15
		$a_03_3 = {67 32 15 66 e7 ?? ?? ?? d6 ed 53 ab } //5
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*5+(#a_01_2  & 1)*15+(#a_03_3  & 1)*5) >=20
 
}
rule Trojan_Win32_Zusy_ARR_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8b d0 48 8b cb ff 15 ?? ?? ?? ?? 4c 89 64 24 30 44 89 64 24 28 4c 89 64 24 20 4c 8b cf 45 33 c0 33 d2 48 8b cb } //3
		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 74 61 73 6b 6d 67 72 2e 65 78 65 20 2f 46 } //7 taskkill /IM taskmgr.exe /F
		$a_81_2 = {64 65 6c 20 2f 73 20 2f 71 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 } //10 del /s /q "C:\Windows\System32
		$a_81_3 = {72 69 63 6b 72 6f 6c 6c 2e 6a 70 67 } //6 rickroll.jpg
		$a_81_4 = {49 44 52 5f 52 49 43 4b 52 4f 4c 4c 5f 4a 50 47 } //4 IDR_RICKROLL_JPG
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*7+(#a_81_2  & 1)*10+(#a_81_3  & 1)*6+(#a_81_4  & 1)*4) >=30
 
}
rule Trojan_Win32_Zusy_ARR_MTB_6{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8b ca f0 0f b1 0e 85 c0 } //3
		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //7 cmd.exe /c vssadmin delete shadows /all /quiet
		$a_81_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //6 cmd.exe /c wbadmin delete catalog -quiet
		$a_81_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //5 cmd.exe /c bcdedit /set {default} recoveryenabled No
		$a_81_4 = {63 69 70 68 65 72 20 2f 65 20 2f 73 3a 43 3a 5c 55 73 65 72 73 } //1 cipher /e /s:C:\Users
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*7+(#a_81_2  & 1)*6+(#a_81_3  & 1)*5+(#a_81_4  & 1)*1) >=22
 
}