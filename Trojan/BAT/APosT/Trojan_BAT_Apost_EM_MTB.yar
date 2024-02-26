
rule Trojan_BAT_Apost_EM_MTB{
	meta:
		description = "Trojan:BAT/Apost.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 61 72 6d 68 6f 73 74 2e 70 64 62 } //01 00  charmhost.pdb
		$a_01_1 = {5f 5f 70 61 79 6c 6f 61 64 } //01 00  __payload
		$a_01_2 = {49 73 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //01 00  IsAdministrator
		$a_01_3 = {52 65 6d 6f 76 65 4c 75 63 6b 79 43 68 61 72 6d } //01 00  RemoveLuckyCharm
		$a_01_4 = {56 4d 45 6e 74 72 79 } //01 00  VMEntry
		$a_01_5 = {45 74 68 65 72 53 68 69 65 6c 64 56 4d 2e 52 75 6e 74 69 6d 65 } //00 00  EtherShieldVM.Runtime
	condition:
		any of ($a_*)
 
}