
rule Trojan_AndroidOS_Rewardsteal_P{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.P,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6b 6b 63 69 62 69 6c 2f } //01 00 
		$a_01_1 = {72 61 6e 64 75 6d 4f 54 50 } //01 00 
		$a_01_2 = {52 65 64 65 65 6d 20 53 75 63 63 65 73 73 66 75 6c 20 61 66 74 65 72 20 32 34 20 68 6f 75 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}