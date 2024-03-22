
rule Trojan_BAT_AgentTesla_FAAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 16 06 6f 90 01 01 00 00 06 8e 69 20 00 10 00 00 1f 40 28 90 01 01 00 00 06 0b 16 06 6f 90 01 01 00 00 06 8e 69 20 00 10 00 00 1f 40 28 90 01 01 00 00 06 0c 06 6f 90 01 01 00 00 06 16 07 06 6f 90 01 01 00 00 06 8e 69 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}