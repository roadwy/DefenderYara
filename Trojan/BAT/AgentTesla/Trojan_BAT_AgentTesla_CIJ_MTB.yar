
rule Trojan_BAT_AgentTesla_CIJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 06 84 28 90 01 03 06 6f 90 01 03 0a 26 09 18 d6 0d 90 00 } //01 00 
		$a_01_1 = {02 11 06 91 13 08 07 11 07 91 13 09 09 11 06 11 08 08 61 11 09 61 b4 9c } //00 00 
	condition:
		any of ($a_*)
 
}