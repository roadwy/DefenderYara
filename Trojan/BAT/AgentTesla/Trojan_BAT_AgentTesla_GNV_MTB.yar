
rule Trojan_BAT_AgentTesla_GNV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {58 4a d2 61 d2 52 20 90 01 03 00 fe 0e 0a 00 00 fe 0c 0a 00 20 90 01 03 00 fe 01 90 00 } //0a 00 
		$a_01_1 = {25 47 fe 0c 01 00 fe 0c 02 00 91 61 d2 52 20 10 00 00 00 fe 0e 0a 00 00 fe 0c 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}