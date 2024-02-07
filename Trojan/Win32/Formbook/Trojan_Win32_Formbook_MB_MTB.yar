
rule Trojan_Win32_Formbook_MB_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {57 41 5f 56 4d 53 49 42 } //03 00  WA_VMSIB
		$a_81_1 = {66 62 63 72 65 61 74 65 75 73 65 72 } //03 00  fbcreateuser
		$a_81_2 = {54 5f 5f 32 33 65 33 31 63 30 55 } //03 00  T__23e31c0U
		$a_81_3 = {62 61 73 65 36 34 42 69 6e 61 72 79 } //03 00  base64Binary
		$a_81_4 = {53 79 73 44 61 74 65 54 69 6d 65 50 69 63 6b 33 32 } //03 00  SysDateTimePick32
		$a_81_5 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 41 } //03 00  GetMonitorInfoA
		$a_00_6 = {61 35 62 4b 62 61 62 77 62 8d 62 a6 62 bc 62 d2 62 e8 62 fe 62 14 62 2a 63 49 63 5b 63 71 63 87 63 9d 63 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 75 73 79 62 6f 64 79 } //01 00  Busybody
		$a_81_1 = {43 68 61 6e 67 65 4d 61 64 72 65 70 6f 72 69 74 65 } //01 00  ChangeMadreporite
		$a_81_2 = {54 6f 43 61 72 74 75 6c 61 72 79 } //01 00  ToCartulary
		$a_81_3 = {46 65 65 6c 44 69 6f 73 67 65 6e 69 6e 33 32 } //01 00  FeelDiosgenin32
		$a_81_4 = {55 6e 6c 6f 63 6b 42 61 64 64 65 6c 65 79 69 74 65 36 34 } //01 00  UnlockBaddeleyite64
		$a_81_5 = {53 68 6f 77 53 70 72 65 63 68 67 65 73 61 6e 67 } //01 00  ShowSprechgesang
		$a_81_6 = {5f 50 61 79 54 65 6c 65 67 6f 6e 79 } //01 00  _PayTelegony
		$a_81_7 = {43 68 6f 6f 73 65 4d 6f 6e 74 61 67 65 33 32 2e 64 6c 6c } //00 00  ChooseMontage32.dll
		$a_00_8 = {78 10 01 00 07 00 } //07 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_MB_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 14 8b 4d 10 8b 55 0c 8b 75 08 31 ff c7 45 f0 00 00 00 00 8b 5d 10 89 1c 24 c7 44 24 04 00 00 00 80 c7 44 24 08 07 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 89 45 d8 89 4d d4 89 55 d0 89 75 cc 89 7d c8 ff 15 } //01 00 
		$a_00_1 = {83 ec 08 31 c9 89 45 e0 8b 45 e0 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d c0 ff 15 } //01 00 
		$a_03_2 = {88 14 08 8b 45 e4 8b 4d dc 0f b6 34 08 89 f2 90 02 07 88 14 08 8b 45 dc 83 c0 01 89 45 dc e9 90 01 01 fe ff ff 90 00 } //01 00 
		$a_01_3 = {53 48 45 6d 70 74 79 52 65 63 79 63 6c 65 42 69 6e 57 } //01 00  SHEmptyRecycleBinW
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {43 72 65 61 74 65 54 68 72 65 61 64 70 6f 6f 6c 54 69 6d 65 72 } //00 00  CreateThreadpoolTimer
	condition:
		any of ($a_*)
 
}