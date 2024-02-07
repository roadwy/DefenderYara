
rule Trojan_Win32_Guloader_BR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 6f 73 73 62 69 74 65 5c 4c 69 74 74 6c 65 5c 49 6e 67 65 6e 6d 61 6e 64 73 6c 61 6e 64 65 74 73 5c 55 64 73 76 76 65 6c 73 65 72 6e 65 73 31 30 39 2e 54 61 61 } //01 00  Crossbite\Little\Ingenmandslandets\Udsvvelsernes109.Taa
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 46 6c 69 67 65 6e 5c 56 65 6c 72 65 74 74 65 74 } //01 00  Software\Fligen\Velrettet
		$a_01_2 = {41 66 74 65 72 70 65 61 6b 5c 41 6c 62 72 6f 6e 7a 65 5c 4d 6f 72 72 69 63 65 2e 50 61 6b } //01 00  Afterpeak\Albronze\Morrice.Pak
		$a_01_3 = {52 61 74 69 6e 67 73 6b 65 6d 61 65 74 5c 59 64 65 72 76 67 73 65 6c 65 6d 65 6e 74 65 74 5c 4d 65 6e 6e 65 73 6b 65 61 6c 64 72 65 6e 65 73 2e 6c 6e 6b } //01 00  Ratingskemaet\Ydervgselementet\Menneskealdrenes.lnk
		$a_01_4 = {54 72 61 63 68 65 69 74 69 73 5c 44 61 6d 65 66 72 69 73 72 69 6e 64 65 72 6e 65 5c 52 6b 65 66 6a 65 6e 64 65 2e 41 72 6d 32 34 34 } //01 00  Tracheitis\Damefrisrinderne\Rkefjende.Arm244
		$a_01_5 = {54 65 73 74 6b 72 73 6c 65 72 6e 65 5c 53 75 62 71 75 61 6c 69 74 79 5c 49 6e 74 65 67 72 61 74 69 6f 6e 65 72 5c 42 65 64 73 70 72 65 61 64 73 2e 64 6c 6c } //00 00  Testkrslerne\Subquality\Integrationer\Bedspreads.dll
	condition:
		any of ($a_*)
 
}