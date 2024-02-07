
rule TrojanDownloader_Win32_Ufraie_A{
	meta:
		description = "TrojanDownloader:Win32/Ufraie.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb 0a 00 00 00 c7 45 f8 06 00 00 00 } //01 00 
		$a_01_1 = {99 f7 f9 89 55 f0 83 fa 21 } //01 00 
		$a_01_2 = {be 0a 00 00 00 bf 06 00 00 00 c7 45 fc 08 00 00 00 c7 45 f8 0a 00 00 00 } //01 00 
		$a_01_3 = {c7 45 e8 09 00 00 00 c7 45 e4 03 00 00 00 bb 03 00 00 00 } //01 00 
		$a_01_4 = {bb 03 00 00 00 c7 45 e0 0a 00 00 00 c7 45 dc 08 00 00 00 } //01 00 
		$a_01_5 = {b9 14 00 00 00 99 f7 f9 } //01 00 
		$a_01_6 = {bb 01 00 00 00 be 09 00 00 00 c7 45 cc 07 00 00 00 c7 45 c8 08 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Ufraie_A_2{
	meta:
		description = "TrojanDownloader:Win32/Ufraie.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 4a 57 72 6f 6b 5c 6a 72 6e 41 6f 78 5c 67 74 45 59 2e 70 64 62 } //01 00  C:\JWrok\jrnAox\gtEY.pdb
		$a_01_1 = {4c 3a 5c 59 67 62 59 68 6f 76 6d 5c 61 77 78 5a 43 63 63 5c 6c 6c 64 62 73 66 2e 70 64 62 } //01 00  L:\YgbYhovm\awxZCcc\lldbsf.pdb
		$a_01_2 = {54 3a 5c 79 4d 65 41 6c 42 79 72 5c 73 71 57 64 42 5c 41 7a 64 7a 66 5c 7a 70 57 44 2e 70 64 62 } //01 00  T:\yMeAlByr\sqWdB\Azdzf\zpWD.pdb
		$a_01_3 = {59 3a 5c 71 64 67 63 42 62 6d 79 5c 6b 6a 6c 57 76 61 4e 5c 4f 53 78 66 62 76 74 5c 79 6e 61 66 6c 5c 76 69 66 49 72 7a 2e 70 64 62 } //00 00  Y:\qdgcBbmy\kjlWvaN\OSxfbvt\ynafl\vifIrz.pdb
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Ufraie_A_3{
	meta:
		description = "TrojanDownloader:Win32/Ufraie.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 09 30 04 08 40 3b 45 fc 72 f7 66 8b 01 66 3d 5a 4d 74 13 66 3d 4d 5a 74 0d } //00 00 
	condition:
		any of ($a_*)
 
}