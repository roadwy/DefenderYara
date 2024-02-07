
rule Trojan_Win32_NSISInject_RPO_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f0 38 88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 ac 00 00 00 88 55 ff 0f b6 45 ff f7 d8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPO_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 6f 6e 64 79 6c 75 73 2e 52 65 69 } //01 00  Spondylus.Rei
		$a_01_1 = {48 6f 6c 6f 63 65 6e 74 72 69 64 2e 53 74 75 } //01 00  Holocentrid.Stu
		$a_01_2 = {52 65 67 65 6c 66 61 73 74 73 74 74 65 6c 73 65 72 6e 65 73 2e 64 6c 6c } //01 00  Regelfaststtelsernes.dll
		$a_01_3 = {48 79 70 6e 6f 74 68 65 72 61 70 69 73 74 35 30 2e 4e 6f 6e } //01 00  Hypnotherapist50.Non
		$a_01_4 = {4d 69 63 72 6f 67 61 6d 79 5c 42 65 6b 6c 64 74 2e 42 75 73 } //00 00  Microgamy\Bekldt.Bus
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RPO_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 61 00 64 00 73 00 69 00 6e 00 67 00 65 00 6e 00 69 00 72 00 65 00 6e 00 } //01 00  Stadsingeniren
		$a_01_1 = {43 00 68 00 61 00 72 00 74 00 72 00 65 00 73 00 31 00 34 00 31 00 } //01 00  Chartres141
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 73 00 6c 00 61 00 72 00 61 00 66 00 66 00 65 00 6e 00 6c 00 69 00 76 00 5c 00 4f 00 76 00 65 00 6e 00 69 00 5c 00 46 00 6f 00 72 00 73 00 79 00 6e 00 65 00 72 00 5c 00 47 00 6c 00 61 00 74 00 74 00 65 00 64 00 65 00 73 00 } //01 00  Software\slaraffenliv\Oveni\Forsyner\Glattedes
		$a_01_3 = {4c 00 61 00 6e 00 64 00 73 00 68 00 65 00 72 00 72 00 65 00 6e 00 73 00 2e 00 69 00 6e 00 69 00 } //01 00  Landsherrens.ini
		$a_01_4 = {43 00 72 00 6f 00 77 00 66 00 6f 00 6f 00 74 00 65 00 64 00 2e 00 41 00 66 00 74 00 } //00 00  Crowfooted.Aft
	condition:
		any of ($a_*)
 
}