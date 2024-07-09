
rule Trojan_Win32_NSISInject_RE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 b9 0c 00 00 00 f7 f9 8b 45 e0 0f b6 0c 10 8b 55 cc 03 55 fc 0f b6 02 33 c1 8b 4d cc 03 4d fc 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RE_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 92 ?? ?? ?? ?? 30 14 0e f7 d8 0f b6 84 01 ?? ?? ?? ?? 30 44 0e 01 83 c1 02 39 cb 75 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RE_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 80 00 00 6a 32 89 44 24 ?? ff d6 50 6a 31 ff d6 50 33 f6 46 56 57 } //1
		$a_03_1 = {50 c7 45 a8 58 00 00 00 c7 45 b4 ?? ?? ?? ?? c7 45 dc 66 08 88 00 c7 45 ec ?? ?? ?? ?? c7 45 f0 ?? 01 00 00 c7 45 e4 ?? ?? ?? ?? ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_NSISInject_RE_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 79 6e 64 65 72 6e 65 31 35 39 5c 41 74 72 69 63 68 69 63 2e 69 6e 69 } //1 Mynderne159\Atrichic.ini
		$a_01_1 = {52 68 79 6d 65 73 31 31 32 2e 69 6e 69 } //1 Rhymes112.ini
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 43 72 65 6f 73 6f 6c 73 } //1 Software\Creosols
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4b 6c 75 73 69 6c 65 6e 73 } //1 Software\Klusilens
		$a_01_4 = {42 72 6e 64 69 6e 67 65 72 73 2e 64 6c 6c } //1 Brndingers.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RE_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 54 72 61 6b 65 6f 74 6f 6d 69 73 } //1 Software\Trakeotomis
		$a_01_1 = {56 65 6e 69 72 65 6d 65 6e 2e 69 6e 69 } //1 Veniremen.ini
		$a_01_2 = {45 6e 64 6f 73 73 65 72 69 6e 67 73 5c 53 6b 72 66 65 72 65 73 2e 69 6e 69 } //1 Endosserings\Skrferes.ini
		$a_01_3 = {43 61 72 65 74 74 61 2e 53 63 72 } //1 Caretta.Scr
		$a_01_4 = {55 6e 69 6e 73 74 61 6c 6c 5c 46 61 6c 6c 61 6c 69 73 68 6c 79 } //1 Uninstall\Fallalishly
		$a_01_5 = {4e 61 76 69 67 61 74 69 6f 6e 73 73 6b 6f 6c 65 72 } //1 Navigationsskoler
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_NSISInject_RE_MTB_6{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 6e 74 72 61 64 69 6e 67 2e 69 6e 69 } //1 Untrading.ini
		$a_01_1 = {57 72 69 74 65 6f 66 66 73 2e 42 65 71 } //1 Writeoffs.Beq
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 48 75 6d 69 73 74 72 61 74 6f 75 73 } //1 Software\Humistratous
		$a_01_3 = {41 6e 61 6c 79 73 65 70 65 72 69 6f 64 65 72 6e 65 31 34 33 2e 45 66 74 } //1 Analyseperioderne143.Eft
		$a_01_4 = {48 65 6c 62 72 6f 64 65 72 65 6e 2e 6c 6e 6b } //1 Helbroderen.lnk
		$a_01_5 = {41 72 69 73 74 6f 6b 72 61 74 69 73 6b 65 2e 44 64 65 } //1 Aristokratiske.Dde
		$a_01_6 = {41 66 73 6b 72 69 76 6e 69 6e 67 73 6d 75 6c 69 67 68 65 64 65 72 6e 65 2e 42 65 64 } //1 Afskrivningsmulighederne.Bed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}