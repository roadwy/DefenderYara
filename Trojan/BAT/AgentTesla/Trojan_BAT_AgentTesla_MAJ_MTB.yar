
rule Trojan_BAT_AgentTesla_MAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 9f a2 2b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 95 00 00 00 34 00 00 00 73 01 00 00 49 } //05 00 
		$a_01_1 = {65 30 31 62 38 30 33 35 2d 35 34 33 34 2d 34 38 66 39 2d 39 39 35 63 2d 66 66 35 39 39 62 63 61 65 33 30 30 } //05 00  e01b8035-5434-48f9-995c-ff599bcae300
		$a_01_2 = {07 17 58 0b 07 1f 09 fe 04 13 04 11 04 2d 9d 06 17 58 0a 06 1f 09 fe 04 13 05 11 05 2d 8a } //05 00 
		$a_81_3 = {63 79 79 6c 68 67 34 7a 38 36 61 6d 61 35 32 76 62 36 39 74 32 6e 63 37 64 65 36 79 37 6c 78 6b } //00 00  cyylhg4z86ama52vb69t2nc7de6y7lxk
	condition:
		any of ($a_*)
 
}