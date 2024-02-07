
rule Trojan_Win32_QakBot_BA_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 0f 88 01 41 83 ea 90 01 01 75 f5 90 00 } //01 00 
		$a_03_1 = {8b c1 83 e0 90 01 01 8a 44 10 90 01 01 30 04 31 41 3b cf 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_QakBot_BA_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b d8 03 1d 90 02 04 6a 00 e8 90 02 04 2b d8 a1 90 02 04 33 18 89 1d 90 02 04 6a 00 e8 90 02 04 03 05 90 02 04 8b 15 90 02 04 89 02 a1 90 02 04 83 c0 04 a3 90 02 04 33 c0 a3 90 02 04 a1 90 02 04 83 c0 04 03 05 90 02 04 a3 90 02 04 a1 90 02 04 3b 05 90 02 04 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_QakBot_BA_MTB_3{
	meta:
		description = "Trojan:Win32/QakBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {43 33 7a 49 73 62 52 34 75 64 41 } //03 00  C3zIsbR4udA
		$a_01_1 = {43 43 36 50 73 46 } //03 00  CC6PsF
		$a_01_2 = {43 62 4a 56 79 51 30 39 38 76 64 } //03 00  CbJVyQ098vd
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //03 00  DllRegisterServer
		$a_01_4 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //03 00  GetCommandLineA
		$a_01_5 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } //00 00  FindFirstFileExW
	condition:
		any of ($a_*)
 
}