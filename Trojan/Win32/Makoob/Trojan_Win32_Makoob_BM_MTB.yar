
rule Trojan_Win32_Makoob_BM_MTB{
	meta:
		description = "Trojan:Win32/Makoob.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 49 6e 6b 61 73 73 6f 67 65 62 79 72 5c 4e 6f 6e 6e 6f 74 61 62 6c 79 5c 48 75 72 6c 75 6d 68 65 6a 65 74 73 } //01 00  Software\Inkassogebyr\Nonnotably\Hurlumhejets
		$a_01_1 = {47 67 65 68 76 69 64 65 73 74 6f 66 66 65 74 5c 41 73 73 6f 63 69 61 74 69 76 65 6c 79 5c 45 63 68 69 6e 6f 64 65 72 6d 61 2e 69 6e 69 } //01 00  Ggehvidestoffet\Associatively\Echinoderma.ini
		$a_01_2 = {47 6f 72 67 6f 6e 65 69 6f 6e 5c 41 65 74 68 6f 67 65 6e 5c 46 75 6c 6c 65 72 74 6f 6e 2e 42 69 6d } //01 00  Gorgoneion\Aethogen\Fullerton.Bim
		$a_01_3 = {42 75 6e 64 70 6c 61 63 65 72 69 6e 67 5c 42 61 72 74 73 5c 55 64 6b 72 73 65 6c 73 73 69 67 6e 61 6c 65 74 73 5c 52 65 73 70 6f 73 74 2e 44 69 73 } //01 00  Bundplacering\Barts\Udkrselssignalets\Respost.Dis
		$a_01_4 = {55 6e 73 65 74 74 69 6e 67 5c 42 61 67 62 65 6e 73 2e 69 6e 69 } //00 00  Unsetting\Bagbens.ini
	condition:
		any of ($a_*)
 
}