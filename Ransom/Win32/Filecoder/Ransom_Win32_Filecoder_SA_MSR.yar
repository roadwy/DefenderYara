
rule Ransom_Win32_Filecoder_SA_MSR{
	meta:
		description = "Ransom:Win32/Filecoder.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_1 = {47 65 74 44 72 69 76 65 54 79 70 65 } //01 00  GetDriveType
		$a_01_2 = {57 72 69 74 65 46 69 6c 65 } //01 00  WriteFile
		$a_01_3 = {4f 4e 43 45 20 52 41 4e 53 4f 4d 20 50 41 49 44 } //01 00  ONCE RANSOM PAID
		$a_01_4 = {43 41 4e 20 52 45 43 4f 56 45 52 } //01 00  CAN RECOVER
		$a_01_5 = {59 4f 55 52 20 46 49 4c 45 53 20 45 41 53 49 4c 59 } //00 00  YOUR FILES EASILY
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_SA_MSR_2{
	meta:
		description = "Ransom:Win32/Filecoder.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6b 77 76 68 72 64 69 62 67 6d 6d 70 6b 68 6b 69 64 72 62 79 34 6d 63 63 77 71 70 64 73 35 7a 61 36 75 6f 32 74 68 63 77 35 67 7a 37 35 71 6e 63 76 37 72 62 68 79 61 64 2e 6f 6e 69 6f 6e } //01 00  kwvhrdibgmmpkhkidrby4mccwqpds5za6uo2thcw5gz75qncv7rbhyad.onion
		$a_01_1 = {42 00 79 00 70 00 61 00 73 00 73 00 20 00 4b 00 72 00 65 00 6d 00 65 00 7a 00 } //01 00  Bypass Kremez
		$a_01_2 = {61 00 6b 00 6f 00 2d 00 72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  ako-readme.txt
		$a_01_3 = {45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 } //00 00  ENCRYPTED FILES
	condition:
		any of ($a_*)
 
}