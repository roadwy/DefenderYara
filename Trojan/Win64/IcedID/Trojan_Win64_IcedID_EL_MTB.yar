
rule Trojan_Win64_IcedID_EL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 77 6d 6b 42 64 } //01 00  bwmkBd
		$a_01_1 = {63 6d 65 34 66 68 50 7a 6b 62 } //01 00  cme4fhPzkb
		$a_01_2 = {65 6d 6e 43 46 43 74 59 47 32 30 } //01 00  emnCFCtYG20
		$a_01_3 = {66 78 46 4d 49 49 71 71 38 } //01 00  fxFMIIqq8
		$a_01_4 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //00 00  ijniuashdyguas
	condition:
		any of ($a_*)
 
}