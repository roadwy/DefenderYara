
rule Trojan_BAT_AgentTesla_PSYL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 7b 3f 00 00 04 20 80 30 86 f3 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 00 11 0f 20 6f f0 6c be 5a 90 00 } //02 00 
		$a_01_1 = {7e 01 00 00 04 02 09 16 fe 1c 01 00 00 1b 28 24 00 00 0a 11 07 20 f8 30 12 6a 5a 20 eb 87 ed 72 61 } //02 00 
		$a_03_2 = {fe 0c 00 00 20 10 00 00 00 28 90 01 01 00 00 0a 20 00 00 00 00 28 90 01 01 00 00 0a fe 0c 06 00 28 17 00 00 06 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}