
rule Trojan_AndroidOS_SAgnt_AW_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AW!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 5f 64 61 74 61 } //01 00  send_data
		$a_01_1 = {63 6f 6d 2f 57 53 43 75 62 65 2f 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 2f 53 6d 73 53 65 72 76 69 63 65 } //01 00  com/WSCube/ControlPanel/SmsService
		$a_01_2 = {70 65 72 66 6f 72 6d 50 6f 73 74 43 61 6c 6c } //01 00  performPostCall
		$a_01_3 = {43 6f 64 65 46 72 6f 6d 50 61 6e 65 6c } //01 00  CodeFromPanel
		$a_01_4 = {73 65 6e 64 65 64 5f 63 6f 64 65 32 } //00 00  sended_code2
	condition:
		any of ($a_*)
 
}