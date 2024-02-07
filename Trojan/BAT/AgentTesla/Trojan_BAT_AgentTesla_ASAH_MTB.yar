
rule Trojan_BAT_AgentTesla_ASAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {04 08 07 6f 90 01 01 02 00 0a 28 90 01 01 02 00 0a 13 04 28 90 01 01 01 00 0a 11 04 16 11 04 8e 69 6f 90 01 01 02 00 0a 28 0d 02 00 0a 13 05 7e 90 01 01 00 00 04 2c 17 7e 90 01 01 00 00 04 02 8c 91 00 00 01 11 05 6f 90 01 01 00 00 0a de 03 26 de 00 11 05 13 06 de 06 90 00 } //01 00 
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}