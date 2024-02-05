
rule Trojan_BAT_AgentTesla_MBGI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f 90 01 01 00 00 0a 06 20 bd 97 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 20 76 94 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 14 90 00 } //01 00 
		$a_01_1 = {62 32 30 36 2d 64 33 36 61 34 39 65 66 65 32 61 38 } //00 00 
	condition:
		any of ($a_*)
 
}