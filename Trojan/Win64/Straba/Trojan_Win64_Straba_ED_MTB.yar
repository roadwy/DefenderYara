
rule Trojan_Win64_Straba_ED_MTB{
	meta:
		description = "Trojan:Win64/Straba.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 54 52 52 45 5c 47 54 52 57 51 45 2e 70 64 62 } //01 00  D:\TRRE\GTRWQE.pdb
		$a_01_1 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //01 00  OutputDebugStringA
		$a_01_2 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //01 00  GetModuleFileNameA
		$a_01_3 = {47 65 74 53 63 72 6f 6c 6c 49 6e 66 6f } //01 00  GetScrollInfo
		$a_01_4 = {45 78 74 72 61 63 74 49 63 6f 6e 57 } //00 00  ExtractIconW
	condition:
		any of ($a_*)
 
}