
rule Trojan_Win32_Urelas_JU_MTB{
	meta:
		description = "Trojan:Win32/Urelas.JU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } //01 00  golfinfo.ini
		$a_00_1 = {5c 00 48 00 47 00 44 00 72 00 61 00 77 00 2e 00 64 00 6c 00 6c 00 } //01 00  \HGDraw.dll
		$a_00_2 = {49 00 44 00 52 00 5f 00 42 00 49 00 4e 00 41 00 52 00 59 00 } //01 00  IDR_BINARY
		$a_00_3 = {4e 00 65 00 77 00 62 00 61 00 64 00 75 00 67 00 69 00 2e 00 65 00 78 00 65 00 } //01 00  Newbadugi.exe
		$a_01_4 = {53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 } //01 00  SeDebugPrivilege
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}