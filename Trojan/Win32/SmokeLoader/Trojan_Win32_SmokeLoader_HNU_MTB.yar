
rule Trojan_Win32_SmokeLoader_HNU_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.HNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 6f 73 6f 70 6f 6e 61 7a 75 62 69 72 69 6e } //02 00  Sosoponazubirin
		$a_01_1 = {74 61 6e 75 67 69 77 65 63 65 76 65 77 75 70 65 6e 75 6e 69 6b 75 78 61 67 69 67 69 78 69 7a 65 7a 65 6a } //02 00  tanugiwecevewupenunikuxagigixizezej
		$a_01_2 = {6b 65 6c 65 74 6f 6c 61 7a 65 6b 65 6d 61 6d 61 72 } //02 00  keletolazekemamar
		$a_01_3 = {79 75 76 6f 68 69 62 65 72 69 72 6f 73 69 79 75 63 69 64 61 } //02 00  yuvohiberirosiyucida
		$a_01_4 = {43 65 6e 20 6c 75 6d 61 67 6f 63 61 74 75 6c 65 73 61 6b } //00 00  Cen lumagocatulesak
	condition:
		any of ($a_*)
 
}