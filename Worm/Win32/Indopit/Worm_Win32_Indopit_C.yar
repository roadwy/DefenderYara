
rule Worm_Win32_Indopit_C{
	meta:
		description = "Worm:Win32/Indopit.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 65 79 4c 6f 67 67 65 72 20 44 61 72 6b 20 45 76 65 6e 67 67 65 72 } //KeyLogger Dark Evengger  01 00 
		$a_00_1 = {50 00 72 00 65 00 74 00 68 00 6f 00 72 00 79 00 61 00 6e 00 20 00 56 00 4d 00 20 00 54 00 65 00 61 00 6d 00 } //01 00  Prethoryan VM Team
		$a_00_2 = {50 00 72 00 65 00 74 00 68 00 6f 00 72 00 79 00 61 00 6e 00 20 00 56 00 69 00 72 00 75 00 73 00 20 00 56 00 4d 00 } //01 00  Prethoryan Virus VM
		$a_00_3 = {42 00 65 00 6b 00 61 00 73 00 69 00 20 00 7e 00 20 00 49 00 6e 00 64 00 6f 00 6e 00 65 00 73 00 69 00 61 00 } //01 00  Bekasi ~ Indonesia
		$a_00_4 = {64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 77 00 72 00 69 00 74 00 65 00 6c 00 6e 00 28 00 72 00 75 00 6e 00 65 00 78 00 65 00 29 00 } //00 00  document.writeln(runexe)
	condition:
		any of ($a_*)
 
}