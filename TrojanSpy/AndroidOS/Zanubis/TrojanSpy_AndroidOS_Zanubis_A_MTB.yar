
rule TrojanSpy_AndroidOS_Zanubis_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Zanubis.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 65 72 73 6f 6e 61 6c 2f 70 64 66 2f 43 6c 61 73 65 73 2f 43 72 69 70 74 6f 3b } //01 00  Lcom/personal/pdf/Clases/Cripto;
		$a_01_1 = {7a 61 6e 75 62 69 73 } //01 00  zanubis
		$a_01_2 = {70 72 65 66 5f 64 61 74 61 5f 73 6d 73 } //01 00  pref_data_sms
		$a_01_3 = {67 65 74 54 61 72 67 65 74 50 61 63 6b 61 67 65 } //01 00  getTargetPackage
		$a_01_4 = {73 74 72 5f 65 6e 63 72 69 70 74 } //00 00  str_encript
	condition:
		any of ($a_*)
 
}