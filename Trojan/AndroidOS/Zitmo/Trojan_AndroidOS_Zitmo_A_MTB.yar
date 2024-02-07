
rule Trojan_AndroidOS_Zitmo_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Zitmo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 49 6e 69 6e 74 53 6d 73 } //01 00  sendInintSms
		$a_01_1 = {73 65 74 4e 6f 74 46 69 72 73 74 4c 61 75 6e 63 68 } //01 00  setNotFirstLaunch
		$a_01_2 = {73 65 6e 64 53 6d 73 49 66 45 6e 61 62 6c 65 64 } //01 00  sendSmsIfEnabled
		$a_01_3 = {63 6f 6d 2f 73 65 63 75 72 69 74 79 2f 73 65 72 76 69 63 65 } //01 00  com/security/service
		$a_01_4 = {73 65 6e 64 53 6d 73 41 6e 79 77 61 79 } //00 00  sendSmsAnyway
	condition:
		any of ($a_*)
 
}