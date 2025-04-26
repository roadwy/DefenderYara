
rule Trojan_AndroidOS_Fakecalls_MT{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.MT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 53 65 72 76 69 63 65 46 6f 72 77 61 72 20 64 69 6e 67 4e 75 6d 62 65 72 } //1 autoServiceForwar dingNumber
		$a_01_1 = {61 75 74 6f 53 65 72 76 69 63 65 43 61 20 6c 6c 4e 75 6d 62 65 72 } //1 autoServiceCa llNumber
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}