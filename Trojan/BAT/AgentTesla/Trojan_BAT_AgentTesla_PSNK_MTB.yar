
rule Trojan_BAT_AgentTesla_PSNK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c eb 28 02 00 00 0a 06 6f 03 00 00 0a 0b } //02 00 
		$a_01_1 = {28 08 00 00 0a 6f 09 00 00 0a 14 17 8d 06 00 00 01 25 16 07 a2 6f 0a 00 00 0a 75 01 00 00 1b 08 28 0b 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 2a } //00 00 
	condition:
		any of ($a_*)
 
}