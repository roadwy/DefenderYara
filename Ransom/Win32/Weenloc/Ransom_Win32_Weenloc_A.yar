
rule Ransom_Win32_Weenloc_A{
	meta:
		description = "Ransom:Win32/Weenloc.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 01 e8 90 01 04 8b f0 85 f6 74 27 6a 00 56 e8 90 01 04 83 f8 01 1b db 43 56 e8 90 01 04 eb 11 90 00 } //01 00 
		$a_03_1 = {00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 90 01 07 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 55 8b 90 00 } //01 00 
		$a_00_2 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c } //01 00  System\CurrentControlSet\Control\SafeBoot\
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 } //00 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
		$a_00_4 = {5d 04 00 00 b9 } //23 03 
	condition:
		any of ($a_*)
 
}