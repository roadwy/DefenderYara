
rule Trojan_BAT_Zemsil_SM_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 65 6d 70 68 69 6c 6c 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_1 = {74 6f 72 6e 69 6c 6c 6f 34 } //01 00 
		$a_81_2 = {5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 45 71 75 69 6e 6f 78 47 6e 69 65 73 73 5c 4c 65 6e 64 69 6e 67 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 5c 46 69 6e 61 6c 73 5c 61 63 63 6f 75 6e 74 73 2e 61 63 63 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}