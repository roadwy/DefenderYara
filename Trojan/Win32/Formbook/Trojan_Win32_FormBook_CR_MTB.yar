
rule Trojan_Win32_FormBook_CR_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 02 ff 45 90 01 01 81 7d 90 02 30 90 13 90 02 30 8b 45 90 01 01 83 e0 90 02 30 8b 45 90 01 01 8a 80 90 02 20 34 90 01 01 8b 55 90 01 01 03 55 90 01 01 88 02 90 02 30 8b 45 90 01 01 8a 80 90 02 20 8b 55 90 01 01 03 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_CR_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 72 00 69 00 66 00 74 00 73 00 66 00 6f 00 72 00 73 00 74 00 79 00 72 00 72 00 65 00 6c 00 73 00 65 00 72 00 6e 00 65 00 73 00 39 00 } //01 00  Driftsforstyrrelsernes9
		$a_01_1 = {46 00 72 00 65 00 6d 00 73 00 6b 00 72 00 69 00 64 00 74 00 73 00 70 00 61 00 72 00 74 00 69 00 65 00 74 00 37 00 } //01 00  Fremskridtspartiet7
		$a_01_2 = {64 00 69 00 73 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6f 00 6e 00 73 00 61 00 66 00 74 00 61 00 6c 00 65 00 6e 00 } //01 00  distributionsaftalen
		$a_01_3 = {50 00 61 00 72 00 6c 00 69 00 61 00 6d 00 65 00 6e 00 74 00 65 00 72 00 } //01 00  Parliamenter
		$a_01_4 = {74 00 65 00 6b 00 73 00 74 00 6d 00 61 00 6e 00 69 00 70 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 65 00 72 00 6e 00 65 00 73 00 } //01 00  tekstmanipulationernes
		$a_01_5 = {41 00 64 00 67 00 61 00 6e 00 67 00 73 00 65 00 6b 00 73 00 61 00 6d 00 69 00 6e 00 65 00 6e 00 73 00 38 00 } //01 00  Adgangseksaminens8
		$a_01_6 = {6e 00 6f 00 6e 00 72 00 65 00 73 00 6f 00 6c 00 76 00 61 00 62 00 69 00 6c 00 69 00 74 00 79 00 } //01 00  nonresolvability
		$a_01_7 = {44 00 65 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 64 00 39 00 } //01 00  Decontrolled9
		$a_01_8 = {45 00 72 00 69 00 6e 00 64 00 72 00 69 00 6e 00 67 00 73 00 66 00 6f 00 72 00 73 00 6b 00 79 00 64 00 6e 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 36 00 } //01 00  Erindringsforskydningernes6
		$a_00_9 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}