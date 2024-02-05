
rule Trojan_AndroidOS_Banker_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 70 72 69 76 61 74 65 2f 61 64 64 5f 6c 6f 67 2e 70 68 70 } //01 00 
		$a_00_1 = {53 45 41 52 43 48 20 42 41 4e 4b 20 43 4c 49 45 4e 54 } //01 00 
		$a_00_2 = {2f 74 75 6b 5f 74 75 6b 2e 70 68 70 } //01 00 
		$a_00_3 = {2f 70 72 69 76 61 74 62 61 6e 6b 2f } //00 00 
	condition:
		any of ($a_*)
 
}