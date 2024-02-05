
rule Backdoor_BAT_AveMariaRAT_A_MTB{
	meta:
		description = "Backdoor:BAT/AveMariaRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 0b 16 0c 2b 42 16 0d 2b 2c 07 08 09 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 d2 06 28 90 01 01 00 00 06 09 17 58 0d 09 17 fe 04 13 04 11 04 2d ca 06 17 58 0a 08 17 58 0c 08 20 90 01 03 00 fe 04 13 05 11 05 2d b0 7e 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_2 = {54 6f 57 69 6e 33 32 } //00 00 
	condition:
		any of ($a_*)
 
}