
rule Trojan_BAT_AgentTesla_AAVL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 00 65 00 76 00 65 00 72 00 55 00 6e 00 64 00 65 00 72 00 73 00 74 00 61 00 6e 00 64 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  NeverUnderstand.Resources
		$a_01_1 = {49 00 73 00 72 00 61 00 65 00 6c 00 57 00 69 00 6c 00 6c 00 47 00 69 00 76 00 65 00 59 00 6f 00 75 00 54 00 68 00 65 00 52 00 69 00 67 00 68 00 74 00 41 00 6e 00 73 00 77 00 65 00 72 00 } //01 00  IsraelWillGiveYouTheRightAnswer
		$a_01_2 = {43 00 61 00 58 00 42 00 79 00 4e 00 7a 00 } //00 00  CaXByNz
	condition:
		any of ($a_*)
 
}