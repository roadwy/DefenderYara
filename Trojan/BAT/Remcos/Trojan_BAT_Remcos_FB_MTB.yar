
rule Trojan_BAT_Remcos_FB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 5f 37 5f 37 5f 37 5f 37 5f 37 } //01 00  F_7_7_7_7_7
		$a_81_1 = {46 5f 32 5f 32 5f 32 5f 32 5f 32 } //01 00  F_2_2_2_2_2
		$a_81_2 = {58 5f 30 5f 30 5f 30 5f 30 5f 30 } //01 00  X_0_0_0_0_0
		$a_81_3 = {4a 75 73 74 43 68 65 73 73 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  JustChess.Properties
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_7 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_8 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}