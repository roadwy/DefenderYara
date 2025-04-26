
rule Trojan_Win64_Cymuta_AH_MTB{
	meta:
		description = "Trojan:Win64/Cymuta.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 43 79 6d 75 6c 61 74 65 } //3 programdata\Cymulate
		$a_01_1 = {61 74 74 61 63 6b 5f 69 64 } //3 attack_id
		$a_01_2 = {45 44 52 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 } //3 EDR_attacks_path
		$a_01_3 = {44 75 6d 6d 79 53 65 72 76 69 63 65 2e 70 64 62 } //3 DummyService.pdb
		$a_01_4 = {74 65 6d 70 5c 43 59 4d 5f 45 44 52 5f 53 50 52 45 41 44 45 44 2e 74 78 74 } //3 temp\CYM_EDR_SPREADED.txt
		$a_01_5 = {41 74 74 61 63 6b 73 4c 6f 67 73 } //3 AttacksLogs
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}