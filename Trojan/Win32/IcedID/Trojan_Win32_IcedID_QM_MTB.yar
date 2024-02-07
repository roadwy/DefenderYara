
rule Trojan_Win32_IcedID_QM_MTB{
	meta:
		description = "Trojan:Win32/IcedID.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {89 4a 04 89 01 8b ca 81 c1 f0 ff 13 00 8b f1 83 ee 04 c7 06 02 00 00 00 be e0 ff 13 00 2b f3 } //03 00 
		$a_81_1 = {31 30 33 2e 31 37 35 2e 31 36 2e 31 31 33 } //03 00  103.175.16.113
		$a_81_2 = {68 74 6f 6e 73 } //00 00  htons
	condition:
		any of ($a_*)
 
}