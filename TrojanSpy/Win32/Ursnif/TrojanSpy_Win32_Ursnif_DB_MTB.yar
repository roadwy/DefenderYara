
rule TrojanSpy_Win32_Ursnif_DB_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_80_0 = {73 6c 65 65 70 20 41 6e 73 77 65 72 4d 61 6e 79 4d 61 6e 79 4d 61 6e 79 4d 61 6e 79 4d 61 6e 79 20 53 75 62 73 20 } //sleep AnswerManyManyManyManyMany Subs   03 00 
		$a_80_1 = {49 61 4e 69 2c 20 45 20 52 52 52 49 4e 53 49 50 52 } //IaNi, E RRRINSIPR  03 00 
		$a_80_2 = {3d 65 61 20 64 74 64 65 65 6e 77 73 73 52 6e 72 69 74 5b 6e 65 65 45 } //=ea dtdeenwssRnrit[neeE  03 00 
		$a_80_3 = {44 72 69 6e 41 6e 73 77 65 72 4d 61 6e 79 4d 61 6e 79 4d 61 6e 79 4d 61 6e 79 4d 61 6e 79 } //DrinAnswerManyManyManyManyMany  03 00 
		$a_80_4 = {4c 20 4f 54 47 70 54 6e 20 64 20 6f 20 55 6f 5d 20 50 6f 20 45 6e 20 54 20 69 61 52 20 20 72 74 20 64 50 30 79 73 69 4e 20 41 61 } //L OTGpTn d o Uo] Po En T iaR  rt dP0ysiN Aa  03 00 
		$a_80_5 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 57 } //GetSystemDirectoryW  00 00 
	condition:
		any of ($a_*)
 
}