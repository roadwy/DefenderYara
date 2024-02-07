
rule Trojan_AndroidOS_Joker_N_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d 2f 63 78 6a 75 73 } //01 00  .aliyuncs.com/cxjus
		$a_01_1 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00  getClassLoader
		$a_01_2 = {72 71 75 65 73 74 50 68 6f 6e 65 50 65 72 6d 69 73 73 69 6f 6e } //00 00  rquestPhonePermission
	condition:
		any of ($a_*)
 
}