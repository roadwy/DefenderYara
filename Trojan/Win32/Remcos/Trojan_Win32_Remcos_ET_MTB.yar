
rule Trojan_Win32_Remcos_ET_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0b 00 00 14 00 "
		
	strings :
		$a_81_0 = {49 78 6b 64 6f 63 } //14 00  Ixkdoc
		$a_81_1 = {48 66 6b 65 6f 63 } //14 00  Hfkeoc
		$a_81_2 = {64 69 65 6a 63 2e 64 6c 6c } //01 00  diejc.dll
		$a_03_3 = {43 3a 5c 54 45 4d 50 5c 6e 73 90 01 05 2e 74 6d 70 90 00 } //01 00 
		$a_81_4 = {4e 75 6c 6c 73 6f 66 74 49 6e 73 74 } //01 00  NullsoftInst
		$a_81_5 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //01 00  GetTempFileNameA
		$a_81_6 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //01 00  FindFirstFileA
		$a_81_7 = {44 65 6c 65 74 65 46 69 6c 65 41 } //01 00  DeleteFileA
		$a_81_8 = {44 65 6c 65 74 65 20 6f 6e 20 72 65 62 6f 6f 74 } //01 00  Delete on reboot
		$a_81_9 = {45 78 65 63 53 68 65 6c 6c } //01 00  ExecShell
		$a_81_10 = {25 73 25 73 2e 64 6c 6c } //00 00  %s%s.dll
	condition:
		any of ($a_*)
 
}