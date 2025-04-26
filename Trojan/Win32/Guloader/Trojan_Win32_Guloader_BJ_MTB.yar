
rule Trojan_Win32_Guloader_BJ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 68 69 66 66 6f 6e 65 6e 5c 42 72 6f 77 6e 6e 6f 73 65 72 36 35 5c 54 61 72 70 61 70 65 72 5c 4d 65 72 6b 61 6e 74 69 6c 69 73 65 72 69 6e 67 65 72 73 2e 69 6e 69 } //1 Chiffonen\Brownnoser65\Tarpaper\Merkantiliseringers.ini
		$a_01_1 = {41 66 72 65 6a 73 74 65 32 33 35 5c 74 65 74 61 72 74 6f 63 6f 6e 65 5c 4c 69 62 65 6c 69 6e 67 5c 48 79 64 72 61 6d 6e 69 6f 6e 2e 47 72 75 } //1 Afrejste235\tetartocone\Libeling\Hydramnion.Gru
		$a_01_2 = {48 65 6d 61 74 6f 73 65 5c 4d 65 6c 61 6e 69 73 5c 53 70 65 6b 74 72 61 6c 61 6e 61 6c 79 73 65 6e 5c 55 6e 75 72 62 61 6e 65 2e 69 6e 69 } //1 Hematose\Melanis\Spektralanalysen\Unurbane.ini
		$a_01_3 = {4d 61 73 74 6f 64 6f 6e 74 5c 42 69 72 6b 65 73 5c 52 6f 6d 61 6e 74 69 73 6d 65 5c 4c 61 6e 64 68 6f 6c 64 69 6e 67 73 2e 47 6f 6f } //1 Mastodont\Birkes\Romantisme\Landholdings.Goo
		$a_01_4 = {50 65 65 70 75 6c 5c 43 79 74 6f 67 65 6e 65 74 69 6b 6b 65 6e 73 5c 4f 70 67 61 76 65 66 6f 72 6c 6f 65 62 65 74 5c 43 6f 6e 66 65 73 73 6f 72 73 68 69 70 } //1 Peepul\Cytogenetikkens\Opgaveforloebet\Confessorship
		$a_01_5 = {55 6e 73 74 61 67 69 6c 79 5c 4d 69 6e 73 74 72 65 6c 73 5c 52 68 61 70 6f 6e 74 69 6e 5c 44 69 73 67 75 69 73 61 6c 2e 69 6e 69 } //1 Unstagily\Minstrels\Rhapontin\Disguisal.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Guloader_BJ_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 52 00 61 00 76 00 72 00 72 00 65 00 74 00 5c 00 4d 00 65 00 74 00 68 00 6f 00 64 00 6c 00 65 00 73 00 73 00 5c 00 54 00 72 00 6f 00 73 00 6b 00 61 00 62 00 73 00 6c 00 66 00 74 00 65 00 72 00 5c 00 53 00 74 00 72 00 69 00 63 00 6b 00 65 00 6e 00 } //1 Software\Ravrret\Methodless\Troskabslfter\Stricken
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 76 00 69 00 6e 00 67 00 68 00 6a 00 75 00 6c 00 73 00 61 00 72 00 6d 00 5c 00 53 00 6e 00 69 00 74 00 6d 00 6e 00 73 00 74 00 72 00 65 00 74 00 73 00 5c 00 54 00 68 00 69 00 65 00 6e 00 6f 00 6e 00 65 00 } //1 Software\Svinghjulsarm\Snitmnstrets\Thienone
		$a_01_2 = {55 00 6e 00 68 00 65 00 6c 00 6d 00 65 00 64 00 5c 00 70 00 68 00 79 00 73 00 2e 00 69 00 6e 00 69 00 } //1 Unhelmed\phys.ini
		$a_01_3 = {50 00 65 00 6e 00 61 00 6e 00 63 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 Penance.dll
		$a_01_4 = {52 00 61 00 6b 00 65 00 74 00 76 00 72 00 6e 00 73 00 73 00 79 00 73 00 74 00 65 00 6d 00 65 00 72 00 20 00 43 00 68 00 61 00 62 00 61 00 73 00 69 00 74 00 65 00 } //1 Raketvrnssystemer Chabasite
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4e 6f 6e 76 69 73 69 62 69 6c 69 74 69 65 73 5c 42 72 61 64 79 73 65 69 73 6d 61 6c 5c 41 66 73 65 6a 6c 69 6e 67 65 6e 73 } //1 Software\Nonvisibilities\Bradyseismal\Afsejlingens
		$a_01_6 = {59 6e 67 6c 65 64 65 73 25 5c 4b 61 75 74 69 6f 6e 65 6e 73 5c 56 65 6c 63 68 61 6e 6f 73 2e 4b 6f 6d } //1 Yngledes%\Kautionens\Velchanos.Kom
		$a_01_7 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 53 75 6e 64 72 79 6d 65 6e 5c 4b 61 72 74 6f 74 65 6b 73 73 74 79 72 69 6e 67 65 6e 5c 50 61 61 6e 61 65 72 5c 48 6f 65 72 74 65 } //1 CurrentVersion\Uninstall\Sundrymen\Kartoteksstyringen\Paanaer\Hoerte
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 43 68 61 70 6c 69 6e 73 } //1 Software\Chaplins
		$a_01_9 = {41 00 66 00 67 00 69 00 76 00 65 00 6c 00 73 00 65 00 72 00 6e 00 65 00 73 00 20 00 50 00 65 00 72 00 73 00 69 00 73 00 74 00 65 00 6e 00 63 00 65 00 20 00 54 00 61 00 72 00 74 00 65 00 6c 00 65 00 74 00 74 00 65 00 72 00 73 00 } //1 Afgivelsernes Persistence Tarteletters
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}