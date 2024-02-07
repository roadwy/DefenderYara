
rule Trojan_BAT_Keywsec_C{
	meta:
		description = "Trojan:BAT/Keywsec.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 00 2f 00 6d 00 61 00 63 00 2f 00 } //01 00  0/mac/
		$a_01_1 = {6b 00 31 00 34 00 72 00 72 00 75 00 6e 00 } //01 00  k14rrun
		$a_01_2 = {66 00 65 00 61 00 74 00 75 00 72 00 65 00 73 00 2f 00 6e 00 65 00 77 00 2d 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 2f 00 3f 00 76 00 3d 00 } //01 00  features/new-feature/?v=
		$a_01_3 = {76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 73 00 2e 00 63 00 6f 00 6e 00 66 00 } //01 00  versions.conf
		$a_01_4 = {4b 31 34 72 55 70 64 61 74 65 72 00 } //01 00  ㅋ爴灕慤整r
		$a_01_5 = {61 00 48 00 52 00 30 00 63 00 44 00 6f 00 76 00 } //00 00  aHR0cDov
	condition:
		any of ($a_*)
 
}