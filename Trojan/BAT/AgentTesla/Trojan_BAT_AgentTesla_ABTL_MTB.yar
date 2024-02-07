
rule Trojan_BAT_AgentTesla_ABTL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 00 62 00 6f 00 75 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 0b 44 00 6f 00 67 00 67 00 6f 00 00 0d 44 00 6f 00 67 00 67 00 6f 00 31 } //01 00 
		$a_01_1 = {30 33 32 65 37 31 61 33 2d 35 66 65 39 2d 34 36 64 35 2d 61 32 36 36 2d 33 36 65 30 66 31 32 36 33 32 32 62 } //01 00  032e71a3-5fe9-46d5-a266-36e0f126322b
		$a_01_2 = {41 00 62 00 6f 00 75 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  About.Resources
	condition:
		any of ($a_*)
 
}