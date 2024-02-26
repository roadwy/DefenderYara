
rule Trojan_AndroidOS_Rewardsteal_K{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.K,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 59 6f 75 72 20 43 56 56 20 4e 6f } //01 00  Please enter Your CVV No
		$a_01_1 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 59 6f 75 72 20 45 78 70 69 72 79 } //01 00  Please enter Your Expiry
		$a_01_2 = {6b 6d 64 6b 73 61 6d 64 6c 6b 6d 73 61 6c 6b 64 } //00 00  kmdksamdlkmsalkd
	condition:
		any of ($a_*)
 
}