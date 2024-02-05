
rule Backdoor_BAT_Pandora_SP_MTB{
	meta:
		description = "Backdoor:BAT/Pandora.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {18 5b 2b 41 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 08 18 58 16 2d fb 0c 08 18 2c cd 06 16 2d f3 32 d8 19 2c d5 07 2a 90 00 } //01 00 
		$a_81_1 = {44 69 73 63 6f 76 65 72 53 61 6c 65 73 5f 31 2e 65 78 65 } //01 00 
		$a_01_2 = {66 00 69 00 6c 00 69 00 66 00 69 00 6c 00 6d 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 63 00 6f 00 6c 00 6f 00 72 00 73 00 2f 00 70 00 75 00 72 00 70 00 6c 00 65 00 2f 00 42 00 71 00 76 00 6f 00 6f 00 75 00 2e 00 70 00 6e 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}