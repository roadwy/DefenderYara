
rule Backdoor_BAT_Pontoeb_A{
	meta:
		description = "Backdoor:BAT/Pontoeb.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 21 7e 90 01 04 06 9a 6f 90 01 04 7e 90 01 04 06 9a 6f 90 01 04 de 03 26 de 00 06 17 58 0a 06 7e 90 01 04 32 d7 2a 00 90 00 } //01 00 
		$a_00_1 = {6d 00 6f 00 64 00 65 00 3d 00 30 00 26 00 68 00 77 00 69 00 64 00 3d 00 } //01 00 
		$a_01_2 = {6e 55 44 50 46 6c 6f 6f 64 00 } //01 00 
		$a_01_3 = {6e 53 59 4e 46 6c 6f 6f 64 00 } //01 00 
		$a_01_4 = {6e 49 43 4d 50 46 6c 6f 6f 64 00 } //01 00 
		$a_01_5 = {6e 48 54 54 50 46 6c 6f 6f 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}