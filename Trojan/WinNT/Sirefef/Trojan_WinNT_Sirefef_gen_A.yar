
rule Trojan_WinNT_Sirefef_gen_A{
	meta:
		description = "Trojan:WinNT/Sirefef.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c } //01 00 
		$a_00_1 = {50 72 6f 62 65 46 6f 72 52 65 61 64 } //01 00 
		$a_00_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 20 3d 20 25 70 } //01 00 
		$a_00_3 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e } //01 00 
		$a_00_4 = {64 65 6c 65 74 65 20 61 70 63 20 25 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Sirefef_gen_A_2{
	meta:
		description = "Trojan:WinNT/Sirefef.gen!A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c } //01 00 
		$a_01_1 = {50 72 6f 62 65 46 6f 72 52 65 61 64 } //01 00 
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 20 3d 20 25 70 } //01 00 
		$a_01_3 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e } //01 00 
		$a_01_4 = {64 65 6c 65 74 65 20 61 70 63 20 25 } //00 00 
	condition:
		any of ($a_*)
 
}