
rule Trojan_Win32_NSISInject_RPK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 75 6f 6c 5c 61 72 69 74 68 6d 65 74 69 63 2e 69 6e 69 } //01 00  Buol\arithmetic.ini
		$a_81_1 = {73 69 64 65 62 6f 61 72 64 5c 67 65 6e 6f 74 6f 78 69 63 69 74 79 2e 62 69 6e } //01 00  sideboard\genotoxicity.bin
		$a_81_2 = {6d 61 72 6b 65 72 62 6f 61 72 64 5c 73 65 63 72 65 74 61 69 72 65 5c 61 63 63 65 70 74 61 6e 74 2e 74 78 74 } //01 00  markerboard\secretaire\acceptant.txt
		$a_81_3 = {66 61 63 65 6c 65 73 73 2e 64 6f 63 78 } //00 00  faceless.docx
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPK_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 61 72 61 73 69 74 74 65 72 6e 65 } //01 00  Parasitterne
		$a_81_1 = {4d 61 63 61 62 72 65 6e 65 73 73 2e 55 6e 68 } //01 00  Macabreness.Unh
		$a_81_2 = {41 6b 74 69 65 75 72 6f 65 6e 5c 53 6f 70 68 69 73 74 69 63 61 6c 6e 65 73 73 5c 46 6f 72 72 65 74 6e 69 6e 67 73 6f 72 64 65 6e 73 2e 64 6c 6c } //01 00  Aktieuroen\Sophisticalness\Forretningsordens.dll
		$a_81_3 = {47 61 6c 61 63 74 6f 70 79 72 61 6e 6f 73 69 64 65 2e 6c 6e 6b } //01 00  Galactopyranoside.lnk
		$a_81_4 = {48 69 74 73 34 37 2e 54 69 6c } //00 00  Hits47.Til
	condition:
		any of ($a_*)
 
}