
rule Backdoor_BAT_Bladabindi_WA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.WA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 0b 11 04 11 04 6f 90 01 03 0a 1b 6a da 6f 90 01 03 0a 11 04 07 16 1a 6f 90 01 03 0a 26 07 16 28 90 01 03 0a 0c 11 04 16 6a 6f 90 01 03 0a 08 17 da 17 d6 17 da 17 d6 17 da 17 d6 8d 90 01 03 01 0a 09 06 16 08 6f 90 01 03 0a 26 09 90 00 } //01 00 
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  01 00 
		$a_80_2 = {54 6f 41 72 72 61 79 } //ToArray  00 00 
	condition:
		any of ($a_*)
 
}