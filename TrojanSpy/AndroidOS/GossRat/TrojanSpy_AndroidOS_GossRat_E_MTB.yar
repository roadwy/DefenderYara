
rule TrojanSpy_AndroidOS_GossRat_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GossRat.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 65 6c 6c 61 74 } //1 mellat
		$a_01_1 = {4c 69 72 2f 65 78 70 65 72 74 2f 73 6d 73 2f 43 6f 6e 73 74 61 6e 74 73 } //1 Lir/expert/sms/Constants
		$a_01_2 = {4c 69 72 2f 65 78 70 65 72 74 2f 73 6d 73 2f 55 72 6c } //1 Lir/expert/sms/Url
		$a_01_3 = {4c 69 72 2f 65 78 70 65 72 74 2f 73 6d 73 2f 41 70 69 } //1 Lir/expert/sms/Api
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}