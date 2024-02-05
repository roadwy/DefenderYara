
rule Worm_BAT_NWorm_GA_MTB{
	meta:
		description = "Worm:BAT/NWorm.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 30 72 6d 2e 65 78 65 } //01 00 
		$a_80_1 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS  01 00 
		$a_80_2 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  01 00 
		$a_80_3 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 1 & Del  01 00 
		$a_80_4 = {45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 4e 6f 45 78 69 74 20 2d 46 69 6c 65 } //ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -File  01 00 
		$a_80_5 = {72 75 6e 46 69 6c 65 } //runFile  01 00 
		$a_80_6 = {70 6f 6e 67 50 69 6e 67 } //pongPing  00 00 
	condition:
		any of ($a_*)
 
}