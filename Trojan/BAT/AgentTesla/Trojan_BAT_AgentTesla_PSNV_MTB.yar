
rule Trojan_BAT_AgentTesla_PSNV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 0e 11 10 6f 90 01 03 0a 13 11 11 11 16 16 16 16 28 90 01 03 0a 28 90 01 03 0a 2c 2a 11 04 12 11 28 90 01 03 0a 6f a1 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}