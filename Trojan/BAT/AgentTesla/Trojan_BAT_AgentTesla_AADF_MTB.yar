
rule Trojan_BAT_AgentTesla_AADF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 20 dc e2 9d 09 28 90 01 01 00 00 2b 20 59 f4 3b fd 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 7d 90 01 01 00 00 04 11 05 20 a9 d4 22 8e 5a 20 79 8e 67 ed 61 38 90 00 } //01 00 
		$a_01_1 = {51 00 4c 00 51 00 75 00 61 00 6e 00 43 00 46 00 } //00 00  QLQuanCF
	condition:
		any of ($a_*)
 
}