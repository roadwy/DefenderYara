
rule Trojan_BAT_AgentTesla_MBJQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 13 05 06 11 06 5d 13 0a 07 11 05 91 13 0b 09 11 0a 6f 90 01 01 00 00 0a 13 0c 02 07 06 28 90 01 01 00 00 06 13 0d 02 11 0b 11 0c 11 0d 28 90 01 01 00 00 06 13 0e 07 11 05 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d ae 90 00 } //01 00 
		$a_01_1 = {71 75 61 6e 6c 79 62 61 6e 68 61 6e 67 32 30 32 32 } //00 00  quanlybanhang2022
	condition:
		any of ($a_*)
 
}