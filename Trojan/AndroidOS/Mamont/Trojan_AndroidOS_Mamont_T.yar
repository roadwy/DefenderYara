
rule Trojan_AndroidOS_Mamont_T{
	meta:
		description = "Trojan:AndroidOS/Mamont.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 54 65 6c 65 70 68 6f 6e 79 52 61 74 43 6f 6d 6d 61 6e 64 45 78 65 63 75 74 65 64 } //2 onTelephonyRatCommandExecuted
		$a_01_1 = {73 65 6e 64 50 68 6f 6e 65 4e 75 6d 62 65 72 54 6f 52 65 74 72 61 6e 73 6d 69 74 74 65 72 } //2 sendPhoneNumberToRetransmitter
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}