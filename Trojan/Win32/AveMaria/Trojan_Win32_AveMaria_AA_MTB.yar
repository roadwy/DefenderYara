
rule Trojan_Win32_AveMaria_AA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 0d 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 56 45 5f 4d 41 52 49 41 } //01 00 
		$a_80_1 = {58 46 78 44 62 32 31 76 5a 47 39 63 58 45 4e 6f 63 6d 39 74 62 32 52 76 58 46 78 56 63 32 56 79 49 45 52 68 64 47 46 63 58 41 3d 3d } //XFxDb21vZG9cXENocm9tb2RvXFxVc2VyIERhdGFcXA==  01 00 
		$a_80_2 = {5c 42 6c 61 63 6b 20 43 6f 64 69 6e 67 5c 52 41 54 2b 42 4f 54 5c 57 65 62 53 65 72 76 65 72 20 32 2e 30 5c 73 72 63 5c 52 65 6c 65 61 73 65 5c 57 65 62 53 65 72 76 65 72 2e 70 64 62 } //\Black Coding\RAT+BOT\WebServer 2.0\src\Release\WebServer.pdb  0a 00 
		$a_80_3 = {63 32 68 31 64 47 52 76 64 32 35 77 59 77 3d 3d } //c2h1dGRvd25wYw==  0a 00 
		$a_80_4 = {63 6d 56 7a 64 47 46 79 64 47 4a 76 64 41 3d 3d } //cmVzdGFydGJvdA==  0a 00 
		$a_80_5 = {5a 47 39 33 62 6d 78 76 59 57 52 6d 61 57 78 6c } //ZG93bmxvYWRmaWxl  0a 00 
		$a_80_6 = {5a 32 56 30 63 32 4e 79 5a 57 56 75 } //Z2V0c2NyZWVu  0a 00 
		$a_80_7 = {63 33 52 68 63 6e 52 68 63 32 46 6b 62 57 6c 75 5a 58 68 6c } //c3RhcnRhc2FkbWluZXhl  0a 00 
		$a_00_8 = {73 68 75 74 64 6f 77 6e 70 63 } //0a 00 
		$a_00_9 = {72 65 73 74 61 72 74 62 6f 74 } //0a 00 
		$a_00_10 = {64 6f 77 6e 6c 6f 61 64 66 69 6c 65 } //0a 00 
		$a_00_11 = {67 65 74 73 63 72 65 65 6e } //0a 00 
		$a_00_12 = {73 74 61 72 74 61 73 61 64 6d 69 6e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}