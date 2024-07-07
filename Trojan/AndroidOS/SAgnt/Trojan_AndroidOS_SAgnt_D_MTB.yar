
rule Trojan_AndroidOS_SAgnt_D_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 61 6e 64 72 65 73 7a 73 2f 73 6d 73 72 65 63 65 69 76 65 } //1 com/andreszs/smsreceive
		$a_00_1 = {2e 62 65 73 74 6b 65 64 61 69 32 39 2e 63 6f 6d 2f 61 70 69 2f 75 73 65 72 73 6d 73 2f } //1 .bestkedai29.com/api/usersms/
		$a_00_2 = {64 65 66 61 75 6c 74 53 4d 53 44 69 61 6c 6f 67 43 61 6c 6c 62 61 63 6b } //1 defaultSMSDialogCallback
		$a_00_3 = {73 65 6e 64 53 4d 53 50 61 79 6c 6f 61 64 } //1 sendSMSPayload
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}