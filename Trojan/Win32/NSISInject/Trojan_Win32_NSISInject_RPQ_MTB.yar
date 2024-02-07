
rule Trojan_Win32_NSISInject_RPQ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 63 61 74 74 65 72 61 62 6c 65 5c 42 6f 6f 67 79 6d 65 6e } //01 00  Scatterable\Boogymen
		$a_81_1 = {54 65 6f 72 65 74 69 73 65 72 69 6e 67 65 6e } //01 00  Teoretiseringen
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 45 6e 76 69 72 6f 6e 6d 65 6e 74 61 6c 69 73 74 33 30 5c 53 61 74 75 72 61 74 69 6e 67 } //01 00  Software\Environmentalist30\Saturating
		$a_81_3 = {53 69 64 65 72 69 74 65 } //00 00  Siderite
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPQ_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 6f 6e 67 69 69 } //01 00  Congii
		$a_81_1 = {4e 65 63 6b 74 69 65 6c 65 73 73 } //01 00  Necktieless
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 61 66 6d 61 67 72 69 6e 67 65 72 6e 65 } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\afmagringerne
		$a_81_3 = {41 70 70 65 6c 6d 75 6c 69 67 68 65 64 65 72 2e 4f 7a 6f } //00 00  Appelmuligheder.Ozo
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPQ_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 69 00 76 00 69 00 6c 00 62 00 65 00 66 00 6f 00 6c 00 6b 00 6e 00 69 00 6e 00 67 00 } //01 00  Civilbefolkning
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 55 00 62 00 65 00 68 00 61 00 67 00 65 00 6c 00 69 00 67 00 65 00 } //01 00  Software\Ubehagelige
		$a_01_2 = {42 00 72 00 61 00 74 00 74 00 69 00 6e 00 67 00 73 00 62 00 6f 00 72 00 67 00 73 00 } //01 00  Brattingsborgs
		$a_01_3 = {41 00 6e 00 6e 00 65 00 6c 00 6f 00 69 00 64 00 2e 00 41 00 63 00 65 00 } //01 00  Anneloid.Ace
		$a_01_4 = {4d 00 6f 00 6e 00 6f 00 72 00 68 00 69 00 6e 00 61 00 2e 00 73 00 74 00 65 00 } //00 00  Monorhina.ste
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPQ_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 72 00 61 00 73 00 69 00 74 00 74 00 65 00 72 00 6e 00 65 00 } //01 00  Parasitterne
		$a_01_1 = {42 00 69 00 73 00 61 00 6d 00 72 00 6f 00 74 00 74 00 65 00 73 00 2e 00 54 00 69 00 6e 00 } //01 00  Bisamrottes.Tin
		$a_01_2 = {46 00 6f 00 72 00 72 00 65 00 74 00 6e 00 69 00 6e 00 67 00 73 00 6f 00 72 00 64 00 65 00 6e 00 73 00 2e 00 64 00 6c 00 6c 00 } //01 00  Forretningsordens.dll
		$a_01_3 = {47 00 61 00 6c 00 61 00 63 00 74 00 6f 00 70 00 79 00 72 00 61 00 6e 00 6f 00 73 00 69 00 64 00 65 00 2e 00 6c 00 6e 00 6b 00 } //01 00  Galactopyranoside.lnk
		$a_01_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 70 00 66 00 69 00 6e 00 64 00 65 00 72 00 70 00 72 00 69 00 73 00 65 00 72 00 6e 00 65 00 73 00 5c 00 43 00 6f 00 6c 00 6f 00 75 00 72 00 61 00 62 00 6c 00 65 00 6e 00 65 00 73 00 73 00 5c 00 54 00 79 00 76 00 73 00 74 00 6a 00 6c 00 65 00 6e 00 64 00 65 00 5c 00 54 00 6f 00 73 00 69 00 6c 00 79 00 } //00 00  Software\Opfinderprisernes\Colourableness\Tyvstjlende\Tosily
	condition:
		any of ($a_*)
 
}