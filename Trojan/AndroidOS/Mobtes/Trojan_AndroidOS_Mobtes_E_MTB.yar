
rule Trojan_AndroidOS_Mobtes_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Mobtes.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 65 62 63 61 73 68 2e 77 6f 6f 72 69 62 61 6e 6b } //1 webcash.wooribank
		$a_00_1 = {70 68 6f 6e 65 6d 61 6e 61 67 65 72 2f 73 65 72 76 69 63 65 73 2f 62 61 6e 6b 77 65 62 73 65 72 76 69 63 65 3f 77 73 64 6c } //1 phonemanager/services/bankwebservice?wsdl
		$a_00_2 = {63 6d 64 5f 73 74 61 72 74 5f 62 61 6e 6b } //1 cmd_start_bank
		$a_00_3 = {64 65 6c 65 74 65 63 61 6c 6c 6c 6f 67 } //1 deletecalllog
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}