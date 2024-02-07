
rule Trojan_Win32_Zbot_RI_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 44 fa e1 99 e2 c5 c5 75 bf e6 0f 3d 7e 9f 75 e4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RI_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 45 20 43 6f 6f 6b 69 65 73 3a } //01 00  IE Cookies:
		$a_01_1 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 55 66 5c 56 57 58 49 54 3c 41 4b 47 3c 42 } //01 00  zkrvvcnmaebNUf\VWXIT<AKG<B
		$a_01_2 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 62 63 5a } //01 00  zkrvvcnmaebNbcZ
		$a_01_3 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 61 51 54 50 51 47 4d 4a } //01 00  fk{vtelpp]hg[_\HaQTPQGMJ
		$a_01_4 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 58 4d 5a 5b 51 52 49 } //00 00  fk{vtelpp]hg[_\HXMZ[QRI
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RI_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {64 3a 5c 31 31 5c 57 68 65 65 6c 5c 48 65 61 72 64 5c 53 68 6f 75 74 5c 53 74 75 64 65 6e 74 5c 57 65 69 67 68 74 5c 45 78 63 65 70 74 5c 38 37 5c 34 30 5c 35 35 5c 36 39 5c 79 65 6c 6c 6f 77 5c 34 30 5c 54 68 69 6e 6b 2e 70 64 62 } //01 00  d:\11\Wheel\Heard\Shout\Student\Weight\Except\87\40\55\69\yellow\40\Think.pdb
		$a_01_1 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetSystemDirectoryA
		$a_01_2 = {47 65 74 43 50 49 6e 66 6f } //01 00  GetCPInfo
		$a_01_3 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 57 } //01 00  GetLocaleInfoW
		$a_01_4 = {47 65 74 46 69 6c 65 54 79 70 65 } //01 00  GetFileType
		$a_01_5 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 57 } //01 00  GetEnvironmentStringsW
		$a_01_6 = {43 72 65 61 74 65 45 76 65 6e 74 45 78 57 } //01 00  CreateEventExW
		$a_01_7 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //01 00  GetTickCount64
		$a_01_8 = {5f 54 72 61 63 6b 4d 6f 75 73 65 45 76 65 6e 74 } //01 00  _TrackMouseEvent
		$a_01_9 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 45 78 } //01 00  InitializeCriticalSectionEx
		$a_00_10 = {4c 00 43 00 5f 00 43 00 4f 00 4c 00 4c 00 41 00 54 00 45 00 3d 00 43 00 3b 00 4c 00 43 00 5f 00 43 00 54 00 59 00 50 00 45 00 3d 00 43 00 3b 00 4c 00 43 00 5f 00 4d 00 4f 00 4e 00 45 00 54 00 41 00 52 00 59 00 3d 00 43 00 3b 00 4c 00 43 00 5f 00 4e 00 55 00 4d 00 45 00 52 00 49 00 43 00 3d 00 43 00 3b 00 4c 00 43 00 5f 00 54 00 49 00 4d 00 45 00 3d 00 43 00 } //00 00  LC_COLLATE=C;LC_CTYPE=C;LC_MONETARY=C;LC_NUMERIC=C;LC_TIME=C
	condition:
		any of ($a_*)
 
}