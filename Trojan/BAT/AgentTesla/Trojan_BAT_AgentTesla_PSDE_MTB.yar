
rule Trojan_BAT_AgentTesla_PSDE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 06 7e 01 00 00 04 6f 28 90 01 03 00 06 18 6f 29 90 01 03 00 06 18 6f 2a 90 01 03 00 06 6f 2e 90 01 03 0b 02 28 2f 90 01 03 0c 07 08 16 08 8e 69 6f 2c 90 01 03 0d 09 13 04 de 0b 90 00 } //01 00 
		$a_01_1 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_01_2 = {49 45 6e 75 6d 65 72 61 62 6c 65 } //00 00  IEnumerable
	condition:
		any of ($a_*)
 
}