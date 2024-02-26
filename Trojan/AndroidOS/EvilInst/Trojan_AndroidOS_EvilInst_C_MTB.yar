
rule Trojan_AndroidOS_EvilInst_C_MTB{
	meta:
		description = "Trojan:AndroidOS/EvilInst.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6c 61 67 5f 4d 6b 5f 4f 6e 65 } //01 00  Flag_Mk_One
		$a_01_1 = {53 45 4e 44 53 43 } //01 00  SENDSC
		$a_01_2 = {41 66 75 53 65 72 76 69 63 65 } //01 00  AfuService
		$a_01_3 = {6d 6f 64 6f 62 6f 6d 63 6f 2e 63 6f 6d 2f 63 6f 75 6e 74 2d 61 70 70 } //00 00  modobomco.com/count-app
	condition:
		any of ($a_*)
 
}