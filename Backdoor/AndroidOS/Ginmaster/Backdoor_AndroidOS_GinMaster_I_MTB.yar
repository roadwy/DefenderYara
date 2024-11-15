
rule Backdoor_AndroidOS_GinMaster_I_MTB{
	meta:
		description = "Backdoor:AndroidOS/GinMaster.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 72 65 65 6e 6c 6f 67 2e 62 62 } //1 greenlog.bb
		$a_01_1 = {72 61 74 65 5f 6f 6b } //1 rate_ok
		$a_01_2 = {46 41 4b 45 5f 44 4f 4d 41 49 4e 5f 48 41 53 48 } //1 FAKE_DOMAIN_HASH
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}