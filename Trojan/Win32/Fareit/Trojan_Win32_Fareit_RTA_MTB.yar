
rule Trojan_Win32_Fareit_RTA_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 72 69 66 74 73 6b 6f 6e 74 72 6f 6c 76 69 6c 6b 61 61 72 65 6e 65 } //01 00  Driftskontrolvilkaarene
		$a_81_1 = {53 59 47 45 4d 45 4c 44 49 4e 47 53 42 4c 41 4e 4b 45 54 53 } //01 00  SYGEMELDINGSBLANKETS
		$a_81_2 = {71 4e 39 71 43 64 69 31 53 76 76 77 6f 63 57 51 45 53 48 6e 52 31 64 6e 41 31 32 47 41 7a 56 45 33 31 31 34 } //01 00  qN9qCdi1SvvwocWQESHnR1dnA12GAzVE3114
		$a_81_3 = {50 68 6f 74 6f 69 73 6f 6d 65 72 69 7a 61 74 69 6f 6e 34 } //01 00  Photoisomerization4
		$a_81_4 = {53 6b 61 74 74 65 70 6c 69 67 74 73 6f 70 68 72 65 74 } //01 00  Skattepligtsophret
		$a_81_5 = {50 72 6f 64 75 6b 74 69 6f 6e 73 66 65 6a 6c 65 6e 65 73 } //00 00  Produktionsfejlenes
	condition:
		any of ($a_*)
 
}