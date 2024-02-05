
rule Trojan_Win32_Tibs_DG{
	meta:
		description = "Trojan:Win32/Tibs.DG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 5d 14 8d 1c 18 8b 75 10 89 f7 c9 c2 10 00 8d 05 } //01 00 
		$a_01_1 = {45 72 61 73 65 54 61 70 65 00 00 00 46 61 74 61 6c 45 78 69 74 00 47 44 49 33 32 2e 44 4c 4c 00 } //01 00 
		$a_01_2 = {49 57 69 6e 64 6f 77 41 00 00 00 43 72 65 61 74 65 50 6f 70 75 70 4d 65 6e 75 00 57 49 4e 49 4e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tibs_DG_2{
	meta:
		description = "Trojan:Win32/Tibs.DG,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 45 6e 68 4d 65 74 61 46 69 6c 65 00 00 00 45 78 74 46 6c 6f 6f 64 46 69 6c 6c 00 53 48 45 4c } //01 00 
		$a_01_1 = {6f 70 65 72 74 69 65 73 00 00 00 53 48 41 6c 6c } //01 00 
		$a_01_2 = {44 72 61 77 49 6e 73 65 72 74 00 00 00 49 6d 61 67 65 4c 69 73 74 5f 43 6f 70 79 00 00 00 49 6d } //01 00 
		$a_01_3 = {61 67 65 4c 69 73 74 5f 47 65 74 44 72 61 67 49 6d 61 67 65 00 47 44 49 33 32 2e 44 4c 4c 00 } //05 00 
		$a_01_4 = {8b 5d 14 8d 1c 03 8b 75 10 8b 7d 10 c9 c2 10 00 8d 05 } //00 00 
	condition:
		any of ($a_*)
 
}