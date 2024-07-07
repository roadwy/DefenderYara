
rule Trojan_AndroidOS_Hasad_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Hasad.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 70 69 2e 63 6c 69 70 68 6f 74 2e 6d 65 } //1 api.cliphot.me
		$a_01_1 = {54 72 61 63 6b 69 6e 67 53 65 72 76 69 63 65 } //1 TrackingService
		$a_01_2 = {63 6f 6d 2f 68 64 63 2f 73 64 6b 2f 61 75 74 6f 73 75 62 } //1 com/hdc/sdk/autosub
		$a_01_3 = {68 64 63 73 75 62 } //1 hdcsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}