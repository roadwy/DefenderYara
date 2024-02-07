
rule Trojan_BAT_Yakbeex_NZQ_MTB{
	meta:
		description = "Trojan:BAT/Yakbeex.NZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 2a 02 00 70 6f 90 01 01 00 00 0a 00 25 72 40 02 00 70 6f 15 00 00 0a 00 25 16 6f 16 00 00 0a 00 25 17 6f 17 00 00 0a 00 25 17 90 00 } //01 00 
		$a_01_1 = {35 30 31 65 33 66 64 63 2d 35 37 35 64 2d 34 39 32 65 2d 39 30 62 63 2d 37 30 33 66 62 36 32 38 30 65 65 32 } //01 00  501e3fdc-575d-492e-90bc-703fb6280ee2
		$a_81_2 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //00 00  DisableAntiSpyware
	condition:
		any of ($a_*)
 
}