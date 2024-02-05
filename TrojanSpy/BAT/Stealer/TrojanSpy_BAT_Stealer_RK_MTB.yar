
rule TrojanSpy_BAT_Stealer_RK_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {51 32 78 70 5a 57 35 30 4a 51 3d 3d } //Q2xpZW50JQ==  01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00 
		$a_80_2 = {43 3a 5c 55 73 65 72 73 5c 72 69 6e 67 7a 5c 44 6f 63 75 6d 65 6e 74 73 5c 78 52 41 54 20 32 2e 30 5c 78 52 41 54 2d 6d 61 73 74 65 72 5c 43 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 43 6c 69 65 6e 74 2e 70 64 62 } //C:\Users\ringz\Documents\xRAT 2.0\xRAT-master\C\obj\Release\Client.pdb  01 00 
		$a_01_3 = {67 65 74 5f 50 6f 74 65 6e 74 69 61 6c 6c 79 56 75 6c 6e 65 72 61 62 6c 65 50 61 73 73 77 6f 72 64 73 } //01 00 
		$a_01_4 = {41 64 64 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 4c 69 73 74 65 6e 65 72 } //01 00 
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00 
	condition:
		any of ($a_*)
 
}