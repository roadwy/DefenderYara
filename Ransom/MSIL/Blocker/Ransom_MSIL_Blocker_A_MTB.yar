
rule Ransom_MSIL_Blocker_A_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {65 78 70 6f 72 74 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  export HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_1 = {57 69 6e 44 65 66 65 6e 64 65 72 } //01 00  WinDefender
		$a_81_2 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 68 6f 6f 6b } //01 00  Failed to set hook
		$a_81_3 = {53 74 61 72 74 75 70 44 65 6c 61 79 49 6e 4d 53 65 63 } //01 00  StartupDelayInMSec
		$a_81_4 = {5c 42 4c 4f 43 4b 5c 6f 62 6a 5c 44 65 62 75 67 5c 42 4c 4f 43 4b 2e 70 64 62 } //00 00  \BLOCK\obj\Debug\BLOCK.pdb
	condition:
		any of ($a_*)
 
}