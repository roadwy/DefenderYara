
rule Trojan_BAT_AgentTesla_JTJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 06 02 8e 69 6a 5d d4 02 06 02 8e 69 6a 5d d4 91 03 06 03 8e 69 6a 5d d4 91 61 02 06 17 6a 58 02 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //01 00 
		$a_01_1 = {24 30 32 62 36 39 63 64 32 2d 65 66 39 36 2d 34 64 35 32 2d 62 34 64 39 2d 32 31 34 61 32 32 32 38 38 64 31 62 } //00 00  $02b69cd2-ef96-4d52-b4d9-214a22288d1b
	condition:
		any of ($a_*)
 
}