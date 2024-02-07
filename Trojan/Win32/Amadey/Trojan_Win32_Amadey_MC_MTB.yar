
rule Trojan_Win32_Amadey_MC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 66 81 e3 a9 02 c1 c8 6e 66 c1 e9 73 66 03 f8 c1 c2 30 c1 c1 0b 23 c8 66 81 cf 36 02 43 66 be a8 01 66 c1 ca 46 f7 e6 81 ef c8 02 00 00 66 81 e2 5e 02 66 47 0f b6 c0 0f b7 ca 4f c1 e6 30 74 } //05 00 
		$a_01_1 = {5f 6a 62 78 6a 67 62 67 75 79 77 33 40 34 } //00 00  _jbxjgbguyw3@4
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Amadey_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 d0 c3 42 00 e8 35 7e 01 00 59 c3 cc cc cc cc 68 70 c3 42 00 e8 25 7e 01 00 59 c3 cc cc cc cc 6a 20 68 cc 53 43 00 b9 74 bb 43 00 e8 } //02 00 
		$a_01_1 = {41 6d 61 64 65 79 2e 70 64 62 } //02 00  Amadey.pdb
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //02 00  CreateMutexW
		$a_03_3 = {3a 5c 54 45 4d 50 5c 90 02 25 5c 67 68 61 61 65 72 2e 65 78 65 90 00 } //01 00 
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}