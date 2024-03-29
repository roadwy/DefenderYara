
rule Trojan_Win32_Inject_J{
	meta:
		description = "Trojan:Win32/Inject.J,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 } //01 00 
		$a_02_1 = {25 73 25 73 25 73 00 00 5c 00 00 00 90 02 10 2e 65 78 65 00 90 00 } //01 00 
		$a_00_2 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //01 00  Accept-Language: zh-cn
		$a_02_3 = {66 78 68 65 6c 6c 6f 2e 63 66 67 00 2f 6e 63 90 02 03 2f 6d 61 69 6c 2f 61 64 6d 69 6e 49 6e 66 6f 2e 61 73 70 90 00 } //01 00 
		$a_01_4 = {4d 41 43 3d 25 73 26 49 50 3d 25 73 26 4e 41 4d 45 3d 25 73 26 4f 53 3d 25 73 26 4c 41 4e 47 3d 25 73 } //01 00  MAC=%s&IP=%s&NAME=%s&OS=%s&LANG=%s
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 48 6f 74 66 69 78 5c 51 32 34 36 30 30 39 } //00 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix\Q246009
	condition:
		any of ($a_*)
 
}