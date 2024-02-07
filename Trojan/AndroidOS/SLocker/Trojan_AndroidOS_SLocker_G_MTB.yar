
rule Trojan_AndroidOS_SLocker_G_MTB{
	meta:
		description = "Trojan:AndroidOS/SLocker.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 71 71 6d 61 67 69 63 2f } //01 00  Lcom/qqmagic/
		$a_01_1 = {67 65 74 4d 61 69 6c 53 65 72 76 65 72 50 6f 72 74 } //01 00  getMailServerPort
		$a_01_2 = {47 72 65 79 57 6f 6c 66 00 } //01 00 
		$a_01_3 = {70 61 73 73 77 00 } //01 00  慰獳w
		$a_01_4 = {63 72 65 61 74 65 46 6c 6f 61 74 56 69 65 77 } //00 00  createFloatView
	condition:
		any of ($a_*)
 
}