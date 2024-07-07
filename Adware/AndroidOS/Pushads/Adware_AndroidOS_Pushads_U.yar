
rule Adware_AndroidOS_Pushads_U{
	meta:
		description = "Adware:AndroidOS/Pushads.U,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 6d 4a 6d 4d 6f 6e 65 79 } //1 getmJmMoney
		$a_01_1 = {67 65 74 49 6d 67 73 5f 75 72 6c 32 } //1 getImgs_url2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}