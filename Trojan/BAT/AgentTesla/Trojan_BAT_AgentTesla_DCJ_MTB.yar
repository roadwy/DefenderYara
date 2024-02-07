
rule Trojan_BAT_AgentTesla_DCJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 08 18 28 90 01 03 06 1f 10 28 90 01 03 0a 84 28 90 01 03 06 28 90 01 03 06 26 90 00 } //01 00 
		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 06 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_DCJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 34 34 39 42 42 35 37 45 2d 46 33 37 44 2d 34 32 30 37 2d 39 39 43 34 2d 35 43 43 44 41 45 44 30 42 39 35 45 } //01 00  $449BB57E-F37D-4207-99C4-5CCDAED0B95E
		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } //01 00  䜀瑥楐數l
		$a_01_2 = {00 54 6f 49 6e 74 33 32 00 } //01 00 
		$a_01_3 = {00 47 65 74 54 79 70 65 73 00 } //01 00  䜀瑥祔数s
		$a_01_4 = {00 47 65 74 4d 65 74 68 6f 64 73 00 } //01 00  䜀瑥敍桴摯s
		$a_01_5 = {00 47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 00 } //01 00  䜀瑥湅牴䅹獳浥汢y
		$a_01_6 = {08 11 04 02 11 04 91 07 61 06 09 91 61 } //00 00 
	condition:
		any of ($a_*)
 
}