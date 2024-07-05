
rule Trojan_BAT_AgentTesla_SKF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 72 6f 64 75 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Product.Properties.Resources
		$a_81_1 = {2f 2f 31 36 37 2e 31 36 30 2e 31 36 36 2e 32 30 35 2f 31 35 37 31 2e 62 69 6e } //01 00  //167.160.166.205/1571.bin
		$a_00_2 = {00 7e 08 00 00 04 06 7e 08 00 00 04 06 91 20 23 06 00 00 59 d2 9c 00 06 17 58 0a 06 7e 08 00 00 04 8e 69 fe 04 0b 07 2d d7 } //00 00 
	condition:
		any of ($a_*)
 
}