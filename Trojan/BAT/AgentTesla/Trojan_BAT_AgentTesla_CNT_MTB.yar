
rule Trojan_BAT_AgentTesla_CNT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 00 1f 2c 6f 90 01 03 0a 25 26 13 01 38 90 01 03 00 02 28 90 01 03 06 25 26 13 00 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {48 48 47 67 36 35 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}