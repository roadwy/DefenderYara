
rule Trojan_MacOS_OpinionSpy_B_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 53 4d 49 4d 50 51 2e 73 6f 63 6b 65 74 } //01 00  OSMIMPQ.socket
		$a_00_1 = {72 75 6c 65 53 65 63 72 65 63 74 4b 65 79 } //01 00  ruleSecrectKey
		$a_00_2 = {4d 61 63 4d 65 74 65 72 41 67 65 6e 74 } //01 00  MacMeterAgent
		$a_00_3 = {2f 76 61 72 2f 72 75 6e 2f 2e 6f 73 6d 5f 70 71 6d } //00 00  /var/run/.osm_pqm
		$a_00_4 = {5d 04 00 } //00 c0 
	condition:
		any of ($a_*)
 
}