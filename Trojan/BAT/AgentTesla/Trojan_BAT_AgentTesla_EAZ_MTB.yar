
rule Trojan_BAT_AgentTesla_EAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 6f 90 01 01 00 00 0a 18 da 0c 16 0d 2b 19 07 06 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 09 18 d6 0d 09 08 31 e3 90 00 } //02 00 
		$a_01_1 = {31 00 35 00 31 00 5f 00 36 00 39 00 31 00 5f 00 30 00 33 00 33 00 5f 00 30 00 36 00 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}