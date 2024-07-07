
rule Trojan_Win32_Guloader_CC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0e 00 00 "
		
	strings :
		$a_01_0 = {65 6b 73 70 6f 72 74 6c 61 61 6e 65 74 5c 48 61 79 6c 6f 66 74 73 5c 69 74 65 72 5c 62 69 63 79 61 6e 69 64 65 2e 64 6c 6c } //1 eksportlaanet\Haylofts\iter\bicyanide.dll
		$a_01_1 = {61 69 72 73 68 65 64 5c 62 72 65 76 69 61 72 65 72 6e 65 5c 72 65 66 72 69 67 65 72 61 74 69 6f 6e 5c 70 68 69 6c 69 70 2e 65 6d 62 } //1 airshed\breviarerne\refrigeration\philip.emb
		$a_01_2 = {6e 65 64 72 75 6c 6c 65 64 65 73 5c 65 74 68 65 72 65 61 6c 69 7a 61 74 69 6f 6e 73 5c 47 6f 64 61 72 74 65 64 65 32 35 35 5c 77 68 69 73 6b 65 72 73 2e 69 6e 69 } //1 nedrulledes\etherealizations\Godartede255\whiskers.ini
		$a_01_3 = {6b 6f 6d 62 69 6e 61 74 69 6f 6e 73 6d 75 6c 69 67 68 65 64 5c 65 6a 65 6e 64 6f 6d 73 73 65 6c 73 6b 61 62 65 74 5c 67 6f 62 62 6c 65 5c 73 61 64 6c 65 72 2e 6d 6f 6e } //1 kombinationsmulighed\ejendomsselskabet\gobble\sadler.mon
		$a_01_4 = {63 6f 6d 70 75 74 65 73 5c 72 65 64 65 73 69 67 6e 69 6e 67 5c 75 66 6f 72 73 6f 6e 6c 69 67 65 72 65 2e 6c 6e 6b } //1 computes\redesigning\uforsonligere.lnk
		$a_01_5 = {74 61 6e 64 66 79 6c 64 6e 69 6e 67 65 72 6e 65 5c 57 61 72 64 72 6f 62 65 73 36 33 5c 69 76 61 6e 61 73 2e 6c 6e 6b } //1 tandfyldningerne\Wardrobes63\ivanas.lnk
		$a_01_6 = {54 69 6c 62 61 67 65 66 72 73 65 6c 73 5c 6e 67 65 6e 74 2e 74 72 69 } //1 Tilbagefrsels\ngent.tri
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 41 61 62 6e 69 6e 67 73 6b 61 6d 70 65 6e 65 73 5c 44 6f 70 65 72 5c 53 70 6f 72 73 6b 69 66 74 65 72 6e 65 73 31 36 35 5c 46 6c 61 6e 6e 65 6c 66 6c 6f 77 65 72 } //1 Software\Aabningskampenes\Doper\Sporskifternes165\Flannelflower
		$a_01_8 = {45 6c 75 76 69 61 74 65 73 32 33 33 5c 50 75 72 69 73 74 69 63 2e 6c 6e 6b } //1 Eluviates233\Puristic.lnk
		$a_01_9 = {44 79 6b 6e 64 65 72 73 5c 50 68 69 6c 61 6e 74 68 72 6f 70 69 73 65 64 5c 42 65 74 68 6c 65 68 65 6d 69 74 65 5c 53 6f 72 6f 72 69 7a 65 2e 55 66 6c } //1 Dyknders\Philanthropised\Bethlehemite\Sororize.Ufl
		$a_01_10 = {48 61 72 64 66 69 73 74 65 64 6e 65 73 73 32 33 34 5c 55 64 76 69 6b 6c 69 6e 67 73 65 67 6e 65 6e 65 31 38 34 2e 4d 69 63 } //1 Hardfistedness234\Udviklingsegnene184.Mic
		$a_01_11 = {76 61 6c 64 72 61 70 70 65 72 6e 65 5c 4d 61 63 68 69 6e 61 74 69 6f 6e 2e 42 6c 6f } //1 valdrapperne\Machination.Blo
		$a_01_12 = {4b 61 6c 65 6e 64 65 72 6d 65 6e 75 33 38 5c 4a 61 6d 6d 65 72 6c 69 67 73 74 5c 4a 65 6e 6b 6f 6e 74 61 6b 74 65 72 6e 65 73 5c 41 73 79 6e 63 68 72 6f 6e 2e 57 69 6e 32 35 35 } //1 Kalendermenu38\Jammerligst\Jenkontakternes\Asynchron.Win255
		$a_01_13 = {44 65 6d 61 74 65 72 69 61 6c 69 7a 65 64 25 5c 53 69 62 65 6e 73 62 65 74 6e 64 65 6c 73 65 72 2e 47 75 61 } //1 Dematerialized%\Sibensbetndelser.Gua
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=7
 
}