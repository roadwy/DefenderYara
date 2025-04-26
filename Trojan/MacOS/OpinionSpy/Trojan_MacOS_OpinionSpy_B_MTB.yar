
rule Trojan_MacOS_OpinionSpy_B_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4f 53 4d 49 4d 50 51 2e 73 6f 63 6b 65 74 } //1 OSMIMPQ.socket
		$a_00_1 = {72 75 6c 65 53 65 63 72 65 63 74 4b 65 79 } //1 ruleSecrectKey
		$a_00_2 = {4d 61 63 4d 65 74 65 72 41 67 65 6e 74 } //1 MacMeterAgent
		$a_00_3 = {2f 76 61 72 2f 72 75 6e 2f 2e 6f 73 6d 5f 70 71 6d } //1 /var/run/.osm_pqm
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}