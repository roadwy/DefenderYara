
rule Trojan_BAT_AgentTesla_SOJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 64 39 63 64 66 36 62 65 2d 39 39 32 33 2d 34 63 39 39 2d 61 36 62 64 2d 62 61 39 34 37 62 31 33 64 62 61 34 } //01 00  $d9cdf6be-9923-4c99-a6bd-ba947b13dba4
		$a_00_1 = {02 6f 6a 00 00 0a 18 5b 8d 06 00 00 01 0a 16 0b 2b 18 06 07 02 07 18 5a 18 6f 6b 00 00 0a 1f 10 28 6c 00 00 0a 9c 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d de } //00 00 
	condition:
		any of ($a_*)
 
}