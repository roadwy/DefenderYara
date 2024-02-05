
rule Backdoor_BAT_NanoCoreRAT_B_MTB{
	meta:
		description = "Backdoor:BAT/NanoCoreRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 14 72 32 50 02 70 18 8d 17 00 00 01 25 16 72 42 50 02 70 a2 25 17 72 48 50 02 70 a2 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 07 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 0c 28 90 01 01 00 00 0a 14 72 90 00 } //01 00 
		$a_01_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}