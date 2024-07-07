
rule Trojan_AndroidOS_Agent_RA_MTB{
	meta:
		description = "Trojan:AndroidOS/Agent.RA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 61 6c 69 6d 6f 6e 61 2f 69 76 72 5f 70 72 65 6d 69 75 6d 2f 72 65 63 65 69 76 65 72 73 } //2 Lcom/palimona/ivr_premium/receivers
		$a_00_1 = {49 6e 63 6f 6d 69 6e 67 53 6d 73 52 65 63 65 69 76 65 72 } //1 IncomingSmsReceiver
		$a_00_2 = {4f 75 74 67 6f 69 6e 67 43 61 6c 6c 52 65 63 65 69 76 65 72 } //1 OutgoingCallReceiver
		$a_00_3 = {69 73 41 6c 72 65 61 64 79 4c 69 73 74 65 6e 69 6e 67 } //1 isAlreadyListening
		$a_00_4 = {61 70 69 2e 61 70 70 34 64 77 2e 63 6f 6d } //1 api.app4dw.com
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}