
rule PWS_Win32_Dyzap_A{
	meta:
		description = "PWS:Win32/Dyzap.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 44 59 52 45 5c 52 65 6c 65 61 73 65 5c 7a 61 70 75 73 6b 61 74 6f 72 } //1 \DYRE\Release\zapuskator
		$a_01_1 = {2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 52 00 61 00 6e 00 67 00 69 00 73 00 50 00 69 00 70 00 65 00 } //1 .\pipe\RangisPipe
		$a_01_2 = {41 55 54 4f 42 41 43 4b 43 4f 4e 4e } //1 AUTOBACKCONN
		$a_01_3 = {3d 52 42 53 47 5f 43 4f 52 50 34 50 26 64 6f 6d 61 69 6e 3d } //1 =RBSG_CORP4P&domain=
		$a_01_4 = {48 83 ec 20 ff 55 08 48 8b 4d cc 48 8d 64 cc 20 5f 48 89 45 f4 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule PWS_Win32_Dyzap_A_2{
	meta:
		description = "PWS:Win32/Dyzap.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0b 00 00 "
		
	strings :
		$a_01_0 = {49 54 8f 45 f0 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb 8d 85 b0 fd ff ff 8b c8 89 45 fc 85 c9 } //1
		$a_01_1 = {8a 07 3c ff 75 0d 80 7f 01 25 75 07 8b 47 02 8b 00 eb 19 3c e9 75 09 8b 4f 01 8d 44 39 05 eb 0c 3c eb 75 0f 0f be 57 01 8d 44 3a 02 } //1
		$a_03_2 = {8b 54 24 2c 89 4c 24 ?? 39 51 44 0f 85 ?? ?? 00 00 89 7c 24 1c 39 79 04 0f 86 ?? ?? 00 00 8d 81 dc 00 00 00 89 44 24 ?? eb 07 8d a4 24 00 00 00 00 83 78 10 05 0f 85 ?? ?? 00 00 8b 30 57 ff 15 ?? ?? ?? 00 56 57 6a 10 } //1
		$a_00_3 = {62 74 6e 74 00 00 00 00 73 6c 69 70 00 } //1
		$a_00_4 = {00 41 55 54 4f 42 41 43 4b 43 4f 4e 4e 00 } //1 䄀呕䉏䍁䍋乏N
		$a_00_5 = {2e 73 6f 00 2e 74 6b 00 2e 63 6e 00 2e 68 6b 00 2e 69 6e 00 2e 74 6f 00 2e 77 73 00 2e 63 63 00 } //1 献o琮k挮n栮k椮n琮o眮s挮c
		$a_00_6 = {3c 72 70 63 69 00 00 00 3c 2f 72 70 63 69 3e 00 3f 63 69 64 3d 25 73 00 73 6f 75 72 63 65 68 74 } //1
		$a_00_7 = {6e 6f 74 5f 73 75 70 70 6f 72 74 00 6c 6f 67 70 6f 73 74 00 } //1 潮彴畳灰牯t潬灧獯t
		$a_00_8 = {73 65 6e 64 20 62 72 6f 77 73 6e 61 70 73 68 6f 74 20 66 61 69 6c 65 64 00 } //1
		$a_00_9 = {00 2f 25 73 2f 25 73 2f 25 64 2f 25 73 2f 25 73 2f 00 } //1 ⼀猥┯⽳搥┯⽳猥/
		$a_00_10 = {3d 00 3d 00 47 00 65 00 6e 00 65 00 72 00 61 00 6c 00 3d 00 3d 00 0d 00 0a 00 00 00 3d 00 3d 00 55 00 73 00 65 00 72 00 73 00 3d 00 3d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=4
 
}