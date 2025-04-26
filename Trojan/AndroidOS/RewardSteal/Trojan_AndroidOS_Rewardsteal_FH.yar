
rule Trojan_AndroidOS_Rewardsteal_FH{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.FH,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 78 73 63 61 72 64 2e 6f 6e 72 65 6e 64 65 72 2e 63 6f 6d } //1 axscard.onrender.com
		$a_01_1 = {4c 63 6f 6d 2f 67 75 72 75 6a 69 66 69 6e 64 65 72 2f 6d 6a 70 72 6f } //1 Lcom/gurujifinder/mjpro
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}