
rule Trojan_Win32_NSISInject_RPJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 47 79 72 6f 69 64 61 6c 5c 54 65 6c 65 66 6f 6e 61 6e 6e 6f 6e 63 65 6e 5c 53 70 69 73 65 6f 6c 69 65 72 } //01 00  Software\Gyroidal\Telefonannoncen\Spiseolier
		$a_81_1 = {48 65 6d 61 74 69 6e 69 63 } //01 00  Hematinic
		$a_81_2 = {52 68 65 74 74 2e 69 6e 69 } //01 00  Rhett.ini
		$a_81_3 = {46 6f 72 73 6e 61 6b 6b 65 6c 73 65 } //01 00  Forsnakkelse
		$a_81_4 = {53 6b 6f 76 76 73 6e 65 72 2e 64 6c 6c } //00 00  Skovvsner.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPJ_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 6c 61 73 6d 61 70 68 65 72 65 73 65 73 } //01 00  Plasmaphereses
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 41 6c 6c 65 79 73 5c 44 69 70 6f 72 70 61 } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Alleys\Diporpa
		$a_81_2 = {45 6b 73 74 72 61 61 66 67 69 66 74 2e 6c 6e 6b } //01 00  Ekstraafgift.lnk
		$a_81_3 = {45 66 74 65 72 72 61 74 69 6f 6e 61 6c 69 73 65 72 69 6e 67 73 2e 50 72 65 } //01 00  Efterrationaliserings.Pre
		$a_81_4 = {4d 61 63 72 6f 73 65 69 73 6d 6f 67 72 61 70 68 2e 44 64 73 } //00 00  Macroseismograph.Dds
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPJ_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 6f 00 70 00 65 00 6e 00 64 00 69 00 6e 00 67 00 31 00 37 00 37 00 2e 00 66 00 65 00 61 00 } //01 00  Propending177.fea
		$a_01_1 = {73 00 68 00 61 00 6e 00 74 00 79 00 74 00 6f 00 77 00 6e 00 2e 00 6e 00 6f 00 6e 00 } //01 00  shantytown.non
		$a_01_2 = {4a 00 61 00 70 00 68 00 65 00 74 00 69 00 64 00 65 00 2e 00 6c 00 6e 00 6b 00 } //01 00  Japhetide.lnk
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 46 00 6c 00 61 00 6e 00 67 00 65 00 72 00 73 00 5c 00 44 00 61 00 74 00 61 00 6b 00 6f 00 70 00 69 00 65 00 72 00 69 00 6e 00 67 00 73 00 5c 00 53 00 6b 00 61 00 62 00 73 00 67 00 61 00 6e 00 67 00 65 00 6e 00 65 00 73 00 } //01 00  Software\Flangers\Datakopierings\Skabsgangenes
		$a_01_4 = {4f 00 76 00 65 00 72 00 73 00 6f 00 6f 00 74 00 68 00 69 00 6e 00 67 00 6c 00 79 00 2e 00 65 00 73 00 72 00 } //00 00  Oversoothingly.esr
	condition:
		any of ($a_*)
 
}