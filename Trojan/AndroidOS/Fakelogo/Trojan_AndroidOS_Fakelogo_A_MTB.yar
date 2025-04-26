
rule Trojan_AndroidOS_Fakelogo_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Fakelogo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 79 6f 6e 65 74 5f 6d 61 65 6d 61 78 } //1 byonet_maemax
		$a_01_1 = {6d 6f 73 69 73 6f 66 74 73 } //1 mosisofts
		$a_01_2 = {73 65 6e 64 53 6d 73 } //1 sendSms
		$a_01_3 = {63 6f 6d 2f 64 65 63 72 79 70 74 73 74 72 69 6e 67 6d 61 6e 61 67 65 72 } //1 com/decryptstringmanager
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}