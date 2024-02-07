
rule Trojan_BAT_AgentTesla_JPJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 d8 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 09 17 d6 0d 09 08 31 e4 90 00 } //01 00 
		$a_81_1 = {39 38 34 38 65 37 34 64 2d 32 36 64 30 2d 34 63 65 37 2d 38 31 37 66 2d 62 38 63 39 64 61 66 31 38 39 63 64 } //00 00  9848e74d-26d0-4ce7-817f-b8c9daf189cd
	condition:
		any of ($a_*)
 
}