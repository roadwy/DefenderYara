
rule Trojan_BAT_Spynoon_AAEM_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 02 16 04 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 07 2a 90 00 } //01 00 
		$a_01_1 = {76 00 55 00 30 00 41 00 42 00 73 00 6f 00 75 00 72 00 46 00 42 00 75 00 57 00 6c 00 48 00 36 00 } //01 00  vU0ABsourFBuWlH6
		$a_01_2 = {46 00 6f 00 72 00 65 00 73 00 74 00 49 00 6e 00 68 00 61 00 62 00 69 00 74 00 61 00 6e 00 74 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  ForestInhabitant.Properties.Resources
	condition:
		any of ($a_*)
 
}