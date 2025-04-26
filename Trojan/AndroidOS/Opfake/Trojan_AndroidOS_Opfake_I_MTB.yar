
rule Trojan_AndroidOS_Opfake_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 2f 6f 73 2f 61 6e 64 72 6f 69 64 } //1 net/os/android
		$a_01_1 = {6d 78 63 6c 69 63 6b 2e 63 6f 6d } //1 mxclick.com
		$a_01_2 = {53 4d 53 5f 53 45 4e 54 } //1 SMS_SENT
		$a_01_3 = {55 53 53 44 44 75 6d 62 45 78 74 65 6e 64 65 64 4e 65 74 77 6f 72 6b 53 65 72 76 69 63 65 } //1 USSDDumbExtendedNetworkService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}