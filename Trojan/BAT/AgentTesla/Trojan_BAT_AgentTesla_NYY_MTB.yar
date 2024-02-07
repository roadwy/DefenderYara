
rule Trojan_BAT_AgentTesla_NYY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 00 10 00 00 6f 90 01 03 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f 90 01 03 0a 00 00 00 11 05 90 00 } //01 00 
		$a_01_1 = {24 32 33 62 35 66 31 39 31 2d 35 31 33 61 2d 34 35 34 66 2d 62 62 62 65 2d 65 38 63 31 35 30 32 61 63 37 31 37 } //00 00  $23b5f191-513a-454f-bbbe-e8c1502ac717
	condition:
		any of ($a_*)
 
}