
rule Trojan_BAT_AgentTesla_ABUY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {18 da 13 18 16 13 19 2b 22 07 08 06 11 19 18 6f 90 01 02 00 0a 1f 10 28 90 01 01 01 00 0a 6f 90 01 02 00 0a 00 08 17 d6 0c 11 19 18 d6 13 19 11 19 11 18 31 d8 90 00 } //01 00 
		$a_01_1 = {50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 65 00 64 00 5f 00 53 00 61 00 6c 00 65 00 73 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  Projected_Sales_Project.Resources
	condition:
		any of ($a_*)
 
}