
rule TrojanDropper_Win32_Derusbi_C_dha{
	meta:
		description = "TrojanDropper:Win32/Derusbi.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 1c 0e 88 19 41 4f 75 f7 bf e4 01 00 00 8b ca 03 c7 03 d7 8a 1c 31 80 f3 30 88 19 41 4f } //01 00 
		$a_01_1 = {25 73 5c 25 64 2e 74 6d 70 00 } //01 00 
		$a_01_2 = {25 73 5c 73 71 6c 73 72 76 36 34 2e 64 6c 6c 00 } //01 00  猥獜汱牳㙶⸴汤l
		$a_01_3 = {25 73 5c 73 71 6c 73 72 76 33 32 2e 64 6c 6c 00 } //00 00  猥獜汱牳㍶⸲汤l
	condition:
		any of ($a_*)
 
}