
rule Trojan_AndroidOS_Coper_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 73 66 77 2f 6a 79 62 61 63 67 68 2f 61 76 72 69 78 63 61 62 7a 2f 65 7a 76 71 71 2f 69 64 69 78 7a 64 6e } //1 Lsfw/jybacgh/avrixcabz/ezvqq/idixzdn
		$a_01_1 = {63 6f 6d 2e 76 67 73 75 70 65 72 76 69 73 69 6f 6e 5f 6b 69 74 32 39 2e 63 6f 73 78 6f 31 32 47 } //1 com.vgsupervision_kit29.cosxo12G
		$a_01_2 = {4c 76 76 73 2f 6a 78 76 6c 79 6b 2f 61 63 6f 73 67 72 71 6b 6a 2f 6f 6d 75 75 65 2f 68 68 69 65 64 72 6d 73 72 } //1 Lvvs/jxvlyk/acosgrqkj/omuue/hhiedrmsr
		$a_01_3 = {4c 63 6f 6d 2f 63 65 62 61 7a 75 74 61 7a 61 2f 73 75 76 61 72 61 67 2f 64 61 67 61 6c 2f 78 75 76 75 6c 61 6c 6f 6a 75 2f 73 65 74 6f 70 65 70 69 71 6f 72 } //1 Lcom/cebazutaza/suvarag/dagal/xuvulaloju/setopepiqor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}