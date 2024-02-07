
rule TrojanDropper_BAT_Trosedo_A{
	meta:
		description = "TrojanDropper:BAT/Trosedo.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 } //01 00  \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
		$a_01_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5f 00 42 00 61 00 6e 00 64 00 2e 00 76 00 62 00 73 00 } //01 00  Microsoft_Band.vbs
		$a_01_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5f 00 42 00 61 00 78 00 } //01 00  Microsoft_Bax
		$a_01_3 = {47 61 6d 65 2d 4f 76 65 72 2e 65 78 65 } //01 00  Game-Over.exe
		$a_01_4 = {44 69 6d 20 57 42 6d 56 4f 45 66 71 79 53 4e 44 76 69 64 52 } //00 00  Dim WBmVOEfqySNDvidR
		$a_00_5 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}