
rule Ransom_Win32_Khaminga_A{
	meta:
		description = "Ransom:Win32/Khaminga.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {2e 6c 61 64 6f 6e } //.ladon  01 00 
		$a_80_1 = {43 79 6b 61 20 42 6c 79 6b 61 74 } //Cyka Blykat  01 00 
		$a_80_2 = {63 64 6d 73 78 6f 32 35 79 34 6c 66 68 74 36 76 2e 6f 6e 69 6f 6e 2e 63 61 73 61 } //cdmsxo25y4lfht6v.onion.casa  01 00 
		$a_80_3 = {5c 52 45 41 44 5f 4d 45 2e 68 74 6d 6c } //\READ_ME.html  01 00 
		$a_80_4 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //vssadmin.exe Delete Shadows /All /Quiet  01 00 
		$a_80_5 = {77 6d 69 63 2e 65 78 65 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //wmic.exe shadowcopy delete /nointeractive  00 00 
		$a_00_6 = {5d 04 00 } //00 41 
	condition:
		any of ($a_*)
 
}