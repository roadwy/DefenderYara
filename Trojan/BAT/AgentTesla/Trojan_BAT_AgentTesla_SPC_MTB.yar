
rule Trojan_BAT_AgentTesla_SPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 73 0e 00 00 0a 0d 09 17 6f 90 01 03 0a 09 18 6f 90 01 03 0a 09 0c 08 06 06 1f 10 28 90 01 03 06 6f 90 01 03 0a 13 04 73 12 00 00 0a 13 05 90 00 } //01 00 
		$a_01_1 = {50 00 64 00 49 00 41 00 65 00 44 00 67 00 64 00 55 00 70 00 49 00 36 00 66 00 75 00 58 00 50 00 79 00 71 00 6d 00 72 00 32 00 30 00 65 00 6d 00 4a 00 61 00 47 00 5a 00 50 00 35 00 74 00 69 00 } //00 00  PdIAeDgdUpI6fuXPyqmr20emJaGZP5ti
	condition:
		any of ($a_*)
 
}