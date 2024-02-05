
rule Trojan_BAT_Remcos_EJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 08 03 6f 90 01 03 0a 5d 17 d6 28 90 01 03 0a da 0d 06 09 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 08 17 d6 0c 08 07 31 cd 90 09 07 00 02 08 28 90 01 03 0a 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_2 = {43 6f 6e 76 65 72 74 } //01 00 
		$a_81_3 = {54 6f 53 74 72 69 6e 67 } //01 00 
		$a_81_4 = {52 65 70 6c 61 63 65 } //01 00 
		$a_81_5 = {43 6f 6e 63 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}