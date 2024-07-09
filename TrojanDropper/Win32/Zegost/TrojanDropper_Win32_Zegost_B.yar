
rule TrojanDropper_Win32_Zegost_B{
	meta:
		description = "TrojanDropper:Win32/Zegost.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 49 63 52 6f 53 6f 46 74 5c 77 49 4e 44 6f 57 53 20 6e 74 5c 63 75 72 72 65 6e 74 56 65 72 53 69 6f 4e 5c 73 56 43 68 6f 53 54 } //2 mIcRoSoFt\wINDoWS nt\currentVerSioN\sVChoST
		$a_01_1 = {25 73 6f 74 25 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 25 73 20 25 73 25 73 25 73 } //2 %sot%%\System32\svc%s %s%s%s
		$a_01_2 = {6b 2d 20 65 78 65 2e 74 73 6f 68 } //2 k- exe.tsoh
		$a_01_3 = {72 65 4d 4f 54 65 52 65 47 49 53 63 72 59 } //1 reMOTeReGIScrY
		$a_00_4 = {69 6b 5c 6c 61 62 6f 6c 47 73 25 73 } //1 ik\labolGs%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}
rule TrojanDropper_Win32_Zegost_B_2{
	meta:
		description = "TrojanDropper:Win32/Zegost.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5d 81 ed ?? ?? ?? ?? bb ?? ?? ?? ?? 03 dd b9 ?? ?? ?? ?? ?? 80 33 [0-01] 43 e2 } //2
		$a_01_1 = {6a 65 68 6d 54 69 6d 68 79 73 74 65 68 47 65 74 53 } //2 jehmTimhystehGetS
		$a_03_2 = {83 c4 0c c6 45 ?? 47 c6 45 ?? 6f c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 5c c6 45 ?? 6b c6 45 ?? 69 } //2
		$a_00_3 = {6b 2d 20 65 78 65 2e 74 73 6f 68 } //1 k- exe.tsoh
		$a_00_4 = {69 6b 5c 6c 61 62 6f 6c 47 73 25 73 } //1 ik\labolGs%s
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDropper_Win32_Zegost_B_3{
	meta:
		description = "TrojanDropper:Win32/Zegost.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c } //1 PROFILE%\Application Data\
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 6d 49 63 52 6f 53 6f 46 74 5c 77 49 4e 44 6f 57 53 20 6e 74 5c 63 75 72 72 65 6e 74 56 65 72 53 69 6f 4e 5c 73 56 43 68 6f 53 54 } //1 SOFTWARE\mIcRoSoFt\wINDoWS nt\currentVerSioN\sVChoST
		$a_01_2 = {2e 33 33 32 32 2e 6f 72 67 } //3 .3322.org
		$a_01_3 = {6b 2d 20 65 78 65 2e 74 73 6f 68 } //2 k- exe.tsoh
		$a_00_4 = {25 73 6f 74 25 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 25 73 20 25 73 25 73 25 73 } //3 %sot%%\System32\svc%s %s%s%s
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_00_4  & 1)*3) >=5
 
}
rule TrojanDropper_Win32_Zegost_B_4{
	meta:
		description = "TrojanDropper:Win32/Zegost.B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 11 8b 45 fc 25 ff 00 00 00 33 d0 8b 4d ?? 88 11 } //5
		$a_03_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 16 6a 7a 6a 62 e8 ?? ?? ?? ?? 83 c4 08 8b 55 08 03 55 fc 88 02 eb d9 } //5
		$a_01_2 = {50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c } //1 PROFILE%\Application Data\
		$a_01_3 = {2e 33 33 32 32 2e 6f 72 67 } //1 .3322.org
		$a_01_4 = {6b 2d 20 65 78 65 2e 74 73 6f 68 } //1 k- exe.tsoh
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 6d 49 63 52 6f 53 6f 46 74 5c 77 49 4e 44 6f 57 53 20 6e 74 5c 63 75 72 72 65 6e 74 56 65 72 53 69 6f 4e 5c 73 56 43 68 6f 53 54 } //1 SOFTWARE\mIcRoSoFt\wINDoWS nt\currentVerSioN\sVChoST
		$a_00_6 = {25 73 6f 74 25 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 25 73 20 25 73 25 73 25 73 } //1 %sot%%\System32\svc%s %s%s%s
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=13
 
}