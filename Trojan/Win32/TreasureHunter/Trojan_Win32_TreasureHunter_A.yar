
rule Trojan_Win32_TreasureHunter_A{
	meta:
		description = "Trojan:Win32/TreasureHunter.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 67 61 74 65 2e 70 68 70 } //01 00  /gate.php
		$a_01_1 = {5c 74 72 65 61 73 75 72 65 48 75 6e 74 65 72 5c 52 65 6c 65 61 73 65 5c 74 72 65 61 73 75 72 65 48 75 6e 74 65 72 2e 70 64 62 } //01 00  \treasureHunter\Release\treasureHunter.pdb
		$a_01_2 = {63 6d 64 4c 69 6e 65 44 65 63 72 79 70 74 65 64 } //00 00  cmdLineDecrypted
	condition:
		any of ($a_*)
 
}