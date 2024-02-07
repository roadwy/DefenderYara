
rule Trojan_BAT_AgentTesla_NTK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 03 05 1f 16 5d 6f 90 01 03 0a 61 90 00 } //01 00 
		$a_01_1 = {06 03 04 17 58 20 } //01 00  ̆ᜄ⁘
		$a_01_2 = {06 03 04 17 58 20 00 3e 00 00 5d 91 28 } //01 00 
		$a_01_3 = {5d 03 02 20 00 3e 00 00 04 28 } //00 00 
	condition:
		any of ($a_*)
 
}