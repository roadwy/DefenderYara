
rule Trojan_AndroidOS_Rewardsteal_AF{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AF,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 64 61 76 61 6c 69 62 6c 65 64 } //2 crdavalibled
		$a_01_1 = {73 70 65 72 61 74 65 6d 69 72 67 64 63 61 72 64 } //2 speratemirgdcard
		$a_01_2 = {63 6f 64 65 69 6e 64 75 73 6e 65 77 2f 53 75 63 65 73 73 66 75 6c } //2 codeindusnew/Sucessful
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}