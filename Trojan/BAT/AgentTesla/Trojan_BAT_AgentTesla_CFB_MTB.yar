
rule Trojan_BAT_AgentTesla_CFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 09 18 d6 16 90 00 } //01 00 
		$a_00_1 = {09 11 06 11 08 08 61 11 09 61 b4 9c 11 07 03 } //00 00 
	condition:
		any of ($a_*)
 
}