
rule Trojan_AndroidOS_SpyAgent_AV{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AV,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6c 6c 65 63 74 41 6e 64 53 65 6e 64 43 6f 6e 74 61 63 74 73 } //2 collectAndSendContacts
		$a_01_1 = {63 6f 6c 6c 65 63 74 41 6e 64 53 65 6e 64 43 61 6c 6c 4c 6f 67 } //2 collectAndSendCallLog
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}