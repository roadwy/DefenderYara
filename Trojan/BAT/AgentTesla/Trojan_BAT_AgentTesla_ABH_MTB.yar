
rule Trojan_BAT_AgentTesla_ABH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 e1 01 00 00 95 2e 03 16 2b 01 17 7e 0d 00 00 04 1b 9a 20 69 01 00 00 95 5a 7e 0d 00 00 04 1b 9a 20 c5 00 00 00 95 58 61 80 1d 00 00 04 } //02 00 
		$a_01_1 = {1a 9a 20 70 06 00 00 95 6e 09 0d 31 03 16 2b 01 17 7e 09 00 00 04 1a 9a 20 64 10 00 00 95 5a 7e 09 00 00 04 1a 9a 20 8d 0c 00 00 95 58 61 80 0c 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}