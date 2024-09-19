
rule TrojanSpy_AndroidOS_GossRat_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GossRat.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 72 76 52 65 61 64 } //1 SrvRead
		$a_01_1 = {4c 63 6f 6d 2f 70 73 69 70 68 6f 6e 33 2f 61 70 70 } //5 Lcom/psiphon3/app
		$a_01_2 = {41 75 74 6f 53 74 61 72 74 } //1 AutoStart
		$a_01_3 = {4b 6f 73 41 63 74 69 76 69 74 79 } //5 KosActivity
		$a_01_4 = {73 61 64 65 72 61 74 } //1 saderat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1) >=12
 
}