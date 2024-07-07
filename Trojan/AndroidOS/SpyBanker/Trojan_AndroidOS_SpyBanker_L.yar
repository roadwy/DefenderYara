
rule Trojan_AndroidOS_SpyBanker_L{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.L,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 53 6d 73 53 65 72 76 69 63 65 49 6e 74 65 6e 74 } //1 getSmsServiceIntent
		$a_01_1 = {44 61 74 61 4d 6f 64 65 6c 55 73 65 72 44 61 74 61 28 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 3d } //1 DataModelUserData(phone_number=
		$a_01_2 = {67 65 74 55 73 65 72 5f 61 64 68 61 61 72 } //1 getUser_adhaar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}