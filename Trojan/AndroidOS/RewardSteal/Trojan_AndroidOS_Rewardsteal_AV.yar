
rule Trojan_AndroidOS_Rewardsteal_AV{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AV,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 6b 62 6b 2e 69 6e 2f 6c 6f 6f 6b 2f } //2 kkbk.in/look/
		$a_01_1 = {73 62 69 2f 62 61 6e 6b 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 32 } //2 sbi/bank/MainActivity2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}