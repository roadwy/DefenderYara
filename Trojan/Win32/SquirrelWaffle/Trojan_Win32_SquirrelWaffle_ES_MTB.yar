
rule Trojan_Win32_SquirrelWaffle_ES_MTB{
	meta:
		description = "Trojan:Win32/SquirrelWaffle.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_81_0 = {53 65 6d 69 61 72 69 64 } //03 00  Semiarid
		$a_81_1 = {49 3a 5c 70 69 65 70 6f 75 64 72 65 2e 70 64 62 } //03 00  I:\piepoudre.pdb
		$a_81_2 = {50 3a 5c 6f 73 69 65 72 79 2e 70 64 62 } //03 00  P:\osiery.pdb
		$a_81_3 = {47 3a 5c 73 65 63 74 69 6f 6e 61 72 79 2e 70 64 62 } //03 00  G:\sectionary.pdb
		$a_81_4 = {6e 75 72 73 79 5c 64 61 7a 7a 6c 65 72 } //03 00  nursy\dazzler
		$a_81_5 = {47 65 74 54 65 6d 70 50 61 74 68 57 } //03 00  GetTempPathW
		$a_81_6 = {52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 57 } //03 00  RemoveDirectoryW
		$a_81_7 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //00 00  OutputDebugStringA
	condition:
		any of ($a_*)
 
}