
rule TrojanDropper_Win64_Blusimul_SGA_MTB{
	meta:
		description = "TrojanDropper:Win64/Blusimul.SGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 68 65 63 6b 54 6f 6b 65 6e 4d 65 6d 62 65 72 73 68 69 70 } //CheckTokenMembership  01 00 
		$a_80_1 = {48 65 61 70 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e } //HeapSetInformation  01 00 
		$a_80_2 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //DecryptFileA  01 00 
		$a_80_3 = {77 65 78 74 72 61 63 74 2e 70 64 62 } //wextract.pdb  01 00 
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //Software\Microsoft\Windows\CurrentVersion\RunOnce  01 00 
		$a_80_5 = {77 65 78 74 72 61 63 74 5f 63 6c 65 61 6e 75 70 25 64 } //wextract_cleanup%d  01 00 
		$a_80_6 = {44 6f 49 6e 66 49 6e 73 74 61 6c 6c } //DoInfInstall  01 00 
		$a_80_7 = {42 6c 75 65 73 63 72 65 65 6e 53 69 6d 75 6c 61 74 6f 72 2e 65 78 65 } //BluescreenSimulator.exe  00 00 
	condition:
		any of ($a_*)
 
}