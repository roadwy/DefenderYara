
rule Backdoor_AndroidOS_Climap_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/Climap.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6d 79 6e 65 74 73 65 63 75 72 65 2e 63 68 61 74 73 65 63 75 72 65 } //01 00  com.mynetsecure.chatsecure
		$a_01_1 = {41 6f 77 73 54 65 6d 70 53 65 72 76 69 63 65 32 } //01 00  AowsTempService2
		$a_01_2 = {40 73 79 72 69 61 40 69 6e 74 65 72 6e 65 74 40 } //00 00  @syria@internet@
	condition:
		any of ($a_*)
 
}