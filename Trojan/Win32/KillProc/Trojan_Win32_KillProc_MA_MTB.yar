
rule Trojan_Win32_KillProc_MA_MTB{
	meta:
		description = "Trojan:Win32/KillProc.MA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 07 85 c0 74 03 89 78 04 89 3d 20 86 41 00 68 24 86 41 00 ff 15 14 75 41 00 } //5
		$a_01_1 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_01_2 = {44 69 73 61 62 6c 65 41 6e 74 69 56 69 72 75 73 } //1 DisableAntiVirus
		$a_01_3 = {45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 } //1 EnableLUA /t REG_DWORD /d 0
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}