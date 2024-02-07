
rule Backdoor_BAT_Androm_ABD_MTB{
	meta:
		description = "Backdoor:BAT/Androm.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 08 1f 10 07 28 90 01 03 06 74 90 01 03 1b 6f 90 01 03 0a 00 08 1f 10 07 28 90 01 03 06 74 90 01 03 1b 6f 90 01 03 0a 00 08 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 0d 09 8e 69 1f 10 59 8d 90 01 03 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 1f 10 58 1f 10 59 28 90 01 03 0a 00 11 04 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {50 61 72 73 65 46 61 69 6c 75 72 65 } //01 00  ParseFailure
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {52 00 61 00 79 00 43 00 61 00 73 00 74 00 47 00 61 00 6d 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  RayCastGame.Properties.Resources
	condition:
		any of ($a_*)
 
}