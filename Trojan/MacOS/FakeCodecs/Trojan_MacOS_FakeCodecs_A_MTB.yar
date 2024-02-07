
rule Trojan_MacOS_FakeCodecs_A_MTB{
	meta:
		description = "Trojan:MacOS/FakeCodecs.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 74 6f 70 41 70 70 6c 69 63 61 74 69 6f 6e 73 4f 62 73 65 72 76 65 72 } //02 00  stopApplicationsObserver
		$a_00_1 = {6d 5f 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 53 74 65 70 54 65 78 74 } //02 00  m_installationStepText
		$a_00_2 = {6d 5f 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 53 65 63 6f 6e 64 6f 72 79 54 65 78 74 } //01 00  m_installationSecondoryText
		$a_00_3 = {72 65 6d 6f 76 65 4f 70 65 72 61 42 6c 69 6e 6b 46 72 6f 6d 50 72 6f 66 69 6c 65 57 69 74 68 50 61 74 68 } //00 00  removeOperaBlinkFromProfileWithPath
	condition:
		any of ($a_*)
 
}