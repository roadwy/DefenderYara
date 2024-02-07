
rule Trojan_Win64_Cymuta_AH_MTB{
	meta:
		description = "Trojan:Win64/Cymuta.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 43 79 6d 75 6c 61 74 65 } //03 00  programdata\Cymulate
		$a_01_1 = {61 74 74 61 63 6b 5f 69 64 } //03 00  attack_id
		$a_01_2 = {45 44 52 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 } //03 00  EDR_attacks_path
		$a_01_3 = {44 75 6d 6d 79 53 65 72 76 69 63 65 2e 70 64 62 } //03 00  DummyService.pdb
		$a_01_4 = {74 65 6d 70 5c 43 59 4d 5f 45 44 52 5f 53 50 52 45 41 44 45 44 2e 74 78 74 } //03 00  temp\CYM_EDR_SPREADED.txt
		$a_01_5 = {41 74 74 61 63 6b 73 4c 6f 67 73 } //00 00  AttacksLogs
	condition:
		any of ($a_*)
 
}