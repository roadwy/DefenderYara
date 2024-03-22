
rule Trojan_Win32_Guloader_CL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 74 73 73 74 61 74 65 6e 5c 62 6f 6e 64 65 61 6e 67 65 72 65 6e 73 2e 6c 6e 6b } //01 00  retsstaten\bondeangerens.lnk
		$a_01_1 = {68 6f 75 73 65 77 61 72 6d 65 72 5c 6c 73 6e 69 6e 67 73 6d 6f 64 65 6c 6c 65 6e 73 2e 66 65 72 } //01 00  housewarmer\lsningsmodellens.fer
		$a_01_2 = {6e 6f 6e 67 65 6f 6c 6f 67 69 63 61 6c 5c 75 6e 64 65 72 64 6e 6e 69 6e 67 65 6e 73 2e 69 6e 69 } //01 00  nongeological\underdnningens.ini
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 79 6e 6b 65 6c 69 67 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 65 6e 65 72 67 69 6d 61 72 6b 65 64 5c 6c 65 67 67 79 } //01 00  Software\Microsoft\Windows\ynkelige\Uninstall\energimarked\leggy
		$a_01_4 = {6f 72 6c 6f 67 73 6b 61 70 74 61 6a 6e 65 72 6e 65 5c 54 68 65 72 69 6f 74 72 6f 70 68 69 63 61 6c 2e 69 6e 69 } //01 00  orlogskaptajnerne\Theriotrophical.ini
		$a_01_5 = {74 72 61 63 68 65 61 72 69 61 6e 5c 65 72 79 74 68 72 69 6e 65 2e 4d 6f 75 } //01 00  trachearian\erythrine.Mou
		$a_01_6 = {44 69 65 73 65 6c 6c 6f 6b 6f 6d 6f 74 69 76 65 74 73 25 5c 6c 75 78 65 6d 62 75 72 67 2e 42 65 66 } //01 00  Diesellokomotivets%\luxemburg.Bef
		$a_01_7 = {50 65 75 68 6c 31 35 33 5c 53 69 6e 64 73 73 76 61 67 65 73 74 65 73 2e 63 69 72 } //01 00  Peuhl153\Sindssvagestes.cir
		$a_01_8 = {6e 61 74 69 6f 6e 61 6c 69 6e 64 6b 6f 6d 73 74 65 72 6e 65 73 2e 74 78 74 } //01 00  nationalindkomsternes.txt
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 54 65 6b 73 74 69 6c 61 72 62 65 6a 64 65 72 65 6e 5c 67 61 75 6e 74 6c 65 74 } //00 00  Software\Tekstilarbejderen\gauntlet
	condition:
		any of ($a_*)
 
}