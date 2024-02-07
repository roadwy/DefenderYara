
rule Trojan_BAT_AgentTesla_MBIB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1b 07 08 06 08 91 20 9a 84 00 00 28 90 01 03 06 28 90 01 01 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 df 90 00 } //01 00 
		$a_01_1 = {43 6b 72 6b 69 64 61 7a 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  Ckrkidaz.Properties
	condition:
		any of ($a_*)
 
}