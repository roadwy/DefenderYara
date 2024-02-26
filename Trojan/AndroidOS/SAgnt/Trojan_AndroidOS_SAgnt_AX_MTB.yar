
rule Trojan_AndroidOS_SAgnt_AX_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AX!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 4b 61 6c 69 6e 63 2f 43 6f 6e 74 72 6f 6c 2f 53 6d 73 53 65 72 76 69 63 65 } //01 00  com/Kalinc/Control/SmsService
		$a_01_1 = {43 6f 64 65 46 72 6f 6d 50 61 6e 65 6c } //01 00  CodeFromPanel
		$a_01_2 = {67 65 74 44 65 76 69 63 65 4e 61 6d 65 } //01 00  getDeviceName
		$a_01_3 = {63 6f 64 65 5f 66 72 6f 6d 5f 6d 61 69 6c } //01 00  code_from_mail
		$a_01_4 = {70 65 72 66 6f 72 6d 47 65 74 43 61 6c 6c } //00 00  performGetCall
	condition:
		any of ($a_*)
 
}