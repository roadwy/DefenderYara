
rule Trojan_BAT_AgentTesla_RDM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6d 61 32 74 } //01 00  Sma2t
		$a_01_1 = {45 73 73 36 6e 74 69 61 6c } //01 00  Ess6ntial
		$a_01_2 = {41 38 38 6f 69 6e 74 } //01 00  A88oint
		$a_01_3 = {51 00 6f 00 37 00 44 00 6b 00 58 00 7a 00 6f 00 4b 00 55 00 33 00 2b 00 4d 00 4f 00 6d 00 77 00 66 00 34 00 6c 00 62 00 39 00 77 00 3d 00 3d 00 } //01 00  Qo7DkXzoKU3+MOmwf4lb9w==
		$a_01_4 = {35 00 6b 00 55 00 64 00 45 00 68 00 78 00 59 00 2f 00 39 00 55 00 69 00 37 00 75 00 61 00 58 00 37 00 36 00 52 00 78 00 53 00 41 00 3d 00 3d 00 } //00 00  5kUdEhxY/9Ui7uaX76RxSA==
	condition:
		any of ($a_*)
 
}