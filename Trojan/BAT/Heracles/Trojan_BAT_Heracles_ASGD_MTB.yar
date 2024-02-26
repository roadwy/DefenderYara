
rule Trojan_BAT_Heracles_ASGD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ASGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 06 17 8d 90 01 01 00 00 01 0d 09 16 1f 2c 9d 09 6f 90 01 01 00 00 0a 0b 07 8e 69 18 2f 02 16 2a 07 16 9a 26 07 17 9a 28 90 01 01 00 00 0a 0c 08 16 32 02 17 2a 16 2a 90 00 } //01 00 
		$a_01_1 = {45 00 6e 00 67 00 69 00 6e 00 65 00 44 00 79 00 6e 00 61 00 6d 00 6f 00 43 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 } //01 00  EngineDynamoConfig\Config
		$a_01_2 = {4f 00 76 00 65 00 72 00 68 00 61 00 75 00 6c 00 54 00 69 00 6d 00 65 00 2e 00 63 00 66 00 67 00 } //00 00  OverhaulTime.cfg
	condition:
		any of ($a_*)
 
}