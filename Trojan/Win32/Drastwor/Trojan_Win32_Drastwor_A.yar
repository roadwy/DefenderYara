
rule Trojan_Win32_Drastwor_A{
	meta:
		description = "Trojan:Win32/Drastwor.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 2e 73 74 61 72 } //01 00  *.star
		$a_01_1 = {73 74 61 72 73 64 6f 6f 72 2e 63 6f 6d } //01 00  starsdoor.com
		$a_01_2 = {26 72 65 67 69 73 74 72 61 74 69 6f 6e 3d } //01 00  &registration=
		$a_01_3 = {45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 5c 41 6c 6c 6f 77 } //01 00  Explorer\New Windows\Allow
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_5 = {64 65 20 6c 69 72 65 20 6c 65 20 66 69 63 68 69 65 72 } //01 00  de lire le fichier
		$a_01_6 = {26 6e 6f 63 61 63 68 65 3d } //00 00  &nocache=
	condition:
		any of ($a_*)
 
}