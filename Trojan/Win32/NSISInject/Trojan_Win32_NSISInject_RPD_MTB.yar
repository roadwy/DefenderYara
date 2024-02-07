
rule Trojan_Win32_NSISInject_RPD_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 61 73 74 6f 6f 63 63 69 70 69 74 61 6c 33 33 } //01 00  Mastooccipital33
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 55 6e 62 65 66 72 69 6e 67 65 64 } //01 00  Software\Unbefringed
		$a_81_2 = {50 72 69 6d 69 74 69 76 69 74 65 74 35 30 2e 4b 6e 79 32 35 35 } //01 00  Primitivitet50.Kny255
		$a_81_3 = {53 74 61 74 73 72 65 74 74 65 6e 73 32 39 2e 44 69 73 } //01 00  Statsrettens29.Dis
		$a_81_4 = {46 72 61 67 6d 65 6e 74 65 72 65 6e 64 65 2e 47 74 65 } //00 00  Fragmenterende.Gte
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPD_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4b 69 72 6b 65 67 61 61 72 64 73 6a 6f 72 64 65 6e 65 5c 54 72 75 5c 44 6f 6e 6b 65 79 6d 6e 64 65 6e 65 73 5c 50 61 72 61 6c 79 73 65 72 69 6e 67 65 72 6e 65 73 } //01 00  Software\Kirkegaardsjordene\Tru\Donkeymndenes\Paralyseringernes
		$a_01_1 = {4b 61 79 6f 69 6e 67 2e 64 6c 6c } //01 00  Kayoing.dll
		$a_01_2 = {56 65 6e 69 73 6f 6e 6c 69 6b 65 } //01 00  Venisonlike
		$a_01_3 = {56 61 6e 64 6c 65 64 6e 69 6e 67 73 61 66 67 69 66 74 65 72 } //01 00  Vandledningsafgifter
		$a_01_4 = {54 72 6b 6b 72 6f 67 65 6e 65 73 2e 41 73 73 } //00 00  Trkkrogenes.Ass
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPD_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {75 64 67 69 76 65 6c 73 65 73 64 61 67 65 2e 69 6e 69 } //01 00  udgivelsesdage.ini
		$a_81_1 = {41 62 73 6f 72 62 61 6e 63 79 2e 75 6e 70 } //01 00  Absorbancy.unp
		$a_81_2 = {44 69 73 63 6f 70 6c 61 63 65 6e 74 61 6c 2e 55 6e 6f } //01 00  Discoplacental.Uno
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 46 6c 73 65 6e 5c 4b 61 74 74 65 6c 65 6d 73 5c 4d 79 67 67 65 6e 73 35 38 } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Flsen\Kattelems\Myggens58
		$a_81_4 = {53 70 6f 6e 74 61 6e 73 70 69 6c 6c 65 6e 65 2e 50 72 65 } //00 00  Spontanspillene.Pre
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPD_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 69 00 6d 00 61 00 78 00 5c 00 52 00 69 00 67 00 65 00 72 00 73 00 2e 00 69 00 6e 00 69 00 } //01 00  Climax\Rigers.ini
		$a_01_1 = {52 00 65 00 63 00 69 00 72 00 6b 00 75 00 6c 00 65 00 72 00 65 00 6e 00 64 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //01 00  Recirkulerendes.ini
		$a_01_2 = {64 00 72 00 65 00 6b 00 73 00 2e 00 6c 00 6e 00 6b 00 } //01 00  dreks.lnk
		$a_01_3 = {41 00 6e 00 70 00 61 00 72 00 74 00 73 00 6b 00 61 00 70 00 69 00 74 00 61 00 6c 00 65 00 6e 00 73 00 2e 00 42 00 69 00 7a 00 } //01 00  Anpartskapitalens.Biz
		$a_01_4 = {43 00 6f 00 72 00 72 00 61 00 73 00 69 00 6f 00 6e 00 2e 00 74 00 68 00 6f 00 } //00 00  Corrasion.tho
	condition:
		any of ($a_*)
 
}