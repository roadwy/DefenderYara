
rule Trojan_AndroidOS_Rewardsteal_R{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.R,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 48 44 46 43 5f 52 45 57 41 52 44 5f 41 70 70 32 } //02 00 
		$a_01_1 = {65 78 70 69 72 79 20 73 68 6f 75 6c 64 20 62 65 20 61 74 6c 65 61 73 74 20 32 30 32 33 33 } //00 00 
	condition:
		any of ($a_*)
 
}