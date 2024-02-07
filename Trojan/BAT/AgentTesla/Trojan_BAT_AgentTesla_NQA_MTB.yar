
rule Trojan_BAT_AgentTesla_NQA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 07 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 0c 06 08 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 02 0d 06 6f 90 01 03 0a 09 16 09 8e 69 6f 90 01 03 0a 13 04 de 16 90 00 } //01 00 
		$a_01_1 = {54 6f 42 75 66 66 65 72 } //01 00  ToBuffer
		$a_01_2 = {6e 65 77 4e 6f 64 65 } //01 00  newNode
		$a_01_3 = {69 73 45 6d 70 74 79 } //01 00  isEmpty
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}