
rule Trojan_AndroidOS_Rewardsteal_G{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.G,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 65 6c 6c 20 49 20 63 61 6e 27 74 20 64 6f 20 61 6e 79 74 68 69 6e 67 20 75 6e 74 69 6c 6c 20 79 6f 75 20 70 65 72 6d 69 74 20 6d 65 } //01 00  Well I can't do anything untill you permit me
		$a_01_1 = {6d 70 69 6e 31 5f 62 6f 78 } //00 00  mpin1_box
	condition:
		any of ($a_*)
 
}