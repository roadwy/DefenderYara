
rule Trojan_AndroidOS_Savestealer_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Savestealer.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 70 6e 73 65 72 76 69 63 65 2e 56 68 6f 73 74 73 53 65 72 76 69 63 65 } //1 vpnservice.VhostsService
		$a_01_1 = {61 76 67 67 72 69 70 } //1 avggrip
		$a_01_2 = {77 65 62 68 6f 6f 6b 75 72 6c } //1 webhookurl
		$a_01_3 = {61 6c 6c 6d 61 63 73 } //1 allmacs
		$a_01_4 = {73 74 61 72 74 57 61 74 63 68 69 6e 67 } //1 startWatching
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}