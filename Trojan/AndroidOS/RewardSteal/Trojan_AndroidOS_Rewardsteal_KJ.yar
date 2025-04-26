
rule Trojan_AndroidOS_Rewardsteal_KJ{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.KJ,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 73 52 45 43 45 56 45 70 65 72 } //2 isRECEVEper
		$a_01_1 = {4d 65 73 73 61 67 65 52 65 73 65 76 65 72 } //2 MessageResever
		$a_01_2 = {69 73 53 45 4e 44 70 65 72 } //2 isSENDper
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}