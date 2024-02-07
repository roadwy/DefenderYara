
rule Trojan_Win32_NSISInject_RPI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 61 6c 6c 6f 77 65 72 73 5c 46 6f 72 61 6e 73 74 69 6c 6c 65 74 31 35 35 5c 52 65 74 74 65 70 72 6f 67 72 61 6d 6d 65 72 6e 65 73 31 34 5c 50 61 72 64 68 61 6e } //01 00  Wallowers\Foranstillet155\Retteprogrammernes14\Pardhan
		$a_81_1 = {53 74 6f 77 65 79 2e 50 61 61 } //01 00  Stowey.Paa
		$a_81_2 = {46 6f 72 74 61 6c 65 6e 64 65 73 } //01 00  Fortalendes
		$a_81_3 = {53 61 70 69 64 69 74 79 2e 63 68 69 } //01 00  Sapidity.chi
		$a_81_4 = {53 75 62 61 6e 67 6c 65 64 2e 69 6e 69 } //00 00  Subangled.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPI_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 66 00 74 00 65 00 6e 00 65 00 72 00 5c 00 73 00 65 00 72 00 72 00 75 00 6c 00 61 00 } //01 00  Aftener\serrula
		$a_01_1 = {42 00 65 00 63 00 6f 00 6c 00 6f 00 72 00 5c 00 50 00 65 00 72 00 69 00 63 00 72 00 61 00 6e 00 69 00 75 00 6d 00 5c 00 53 00 63 00 61 00 75 00 74 00 2e 00 50 00 68 00 74 00 } //01 00  Becolor\Pericranium\Scaut.Pht
		$a_01_2 = {55 00 67 00 65 00 6e 00 6e 00 65 00 6d 00 73 00 69 00 67 00 74 00 69 00 67 00 68 00 65 00 64 00 65 00 6e 00 5c 00 46 00 69 00 78 00 61 00 74 00 69 00 6e 00 67 00 5c 00 53 00 61 00 62 00 61 00 6c 00 6f 00 73 00 } //01 00  Ugennemsigtigheden\Fixating\Sabalos
		$a_01_3 = {41 00 64 00 75 00 6c 00 61 00 72 00 65 00 73 00 63 00 65 00 6e 00 63 00 65 00 5c 00 54 00 75 00 64 00 65 00 67 00 72 00 69 00 6d 00 74 00 31 00 35 00 38 00 } //01 00  Adularescence\Tudegrimt158
		$a_01_4 = {42 00 72 00 69 00 63 00 6b 00 77 00 69 00 73 00 65 00 38 00 32 00 2e 00 47 00 6c 00 6f 00 } //01 00  Brickwise82.Glo
		$a_01_5 = {52 00 65 00 61 00 73 00 6f 00 6e 00 61 00 62 00 6c 00 65 00 6e 00 65 00 73 00 73 00 65 00 73 00 } //00 00  Reasonablenesses
	condition:
		any of ($a_*)
 
}