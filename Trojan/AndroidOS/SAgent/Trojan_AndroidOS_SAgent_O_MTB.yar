
rule Trojan_AndroidOS_SAgent_O_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 73 70 2f 73 68 79 79 2f 73 74 61 74 75 73 2e 6a 73 70 } //1 /sp/shyy/status.jsp
		$a_01_1 = {44 59 44 5f 53 4d 53 5f 53 45 4e 44 } //1 DYD_SMS_SEND
		$a_01_2 = {53 65 6e 64 4d 65 73 73 53 65 72 76 69 63 65 } //1 SendMessService
		$a_01_3 = {63 6f 6d 2f 64 64 2f 6c 61 75 6e 63 68 65 72 } //1 com/dd/launcher
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}