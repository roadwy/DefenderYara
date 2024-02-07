
rule Trojan_BAT_AgentTesla_PSKK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 09 00 00 06 28 01 00 00 2b 28 02 00 00 2b 0a de 03 26 de ea } //01 00 
		$a_01_1 = {57 00 77 00 65 00 74 00 77 00 6e 00 61 00 65 00 77 00 6c 00 69 00 79 00 77 00 66 00 6e 00 6e 00 64 00 6d 00 7a 00 7a 00 65 00 } //01 00  Wwetwnaewliywfnndmzze
		$a_01_2 = {48 00 6e 00 7a 00 74 00 70 00 79 00 6c 00 70 00 79 00 76 00 68 00 69 00 67 00 66 00 69 00 6f 00 67 00 6d 00 63 00 } //01 00  Hnztpylpyvhigfiogmc
		$a_01_3 = {6c 00 6c 00 64 00 2e 00 63 00 6d 00 67 00 6f 00 69 00 66 00 67 00 69 00 68 00 76 00 79 00 70 00 6c 00 79 00 70 00 74 00 7a 00 6e 00 48 00 } //00 00  lld.cmgoifgihvyplyptznH
	condition:
		any of ($a_*)
 
}