
rule Trojan_Win32_NSISInject_RB_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 6a 0c 59 f7 f9 8b 45 bc 0f b6 04 10 8b 4d ec 03 4d f4 0f b6 09 33 c8 8b 45 ec 03 45 f4 88 08 eb cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RB_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 6a 40 68 00 30 00 00 68 00 09 3d 00 33 ff 57 ff d3 [0-20] 56 51 68 80 00 00 00 6a 03 51 6a 01 68 00 00 00 80 ff 75 10 ff 15 ?? ?? ?? ?? 8b f0 6a 00 56 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 50 6a 00 89 45 fc ff d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RB_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 72 65 65 6e 65 64 31 35 30 2e 69 6e 69 } //1 Greened150.ini
		$a_01_1 = {42 69 6c 6c 65 74 6b 6f 6e 74 6f 72 73 2e 53 63 79 } //1 Billetkontors.Scy
		$a_01_2 = {45 66 74 65 72 73 6b 72 69 76 65 72 2e 64 6c 6c } //1 Efterskriver.dll
		$a_01_3 = {55 6e 69 6e 73 74 61 6c 6c 5c 54 68 72 61 73 68 65 72 73 } //1 Uninstall\Thrashers
		$a_01_4 = {4f 75 74 62 6c 61 7a 65 5c 6d 69 73 64 69 73 74 72 69 62 75 74 65 2e 69 6e 69 } //1 Outblaze\misdistribute.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RB_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 6c 62 72 6d 61 72 6d 65 6c 61 64 65 73 2e 4b 75 72 } //1 Solbrmarmelades.Kur
		$a_01_1 = {53 74 72 75 6e 6b 65 2e 69 6e 69 } //1 Strunke.ini
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 53 79 73 74 65 6d 66 75 6e 6b 74 69 6f 6e 65 72 6e 65 } //1 Software\Systemfunktionerne
		$a_01_3 = {46 6f 72 62 6c 64 6e 69 6e 67 65 72 73 5c 52 61 74 74 65 64 2e 69 6e 69 } //1 Forbldningers\Ratted.ini
		$a_01_4 = {44 65 6d 6f 6b 72 61 74 69 73 65 72 65 74 2e 56 69 7a } //1 Demokratiseret.Viz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RB_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 65 6c 69 6c 69 74 65 73 5c 54 6b 6b 65 74 } //1 Software\Melilites\Tkket
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 6d 69 73 66 6f 72 74 6f 6c 6b 6e 69 6e 67 65 6e 73 } //1 Software\misfortolkningens
		$a_01_2 = {45 78 70 69 72 65 72 2e 69 6e 69 } //1 Expirer.ini
		$a_01_3 = {4c 69 76 73 66 61 72 65 6e 5c 43 68 72 69 6c 6c 65 73 73 2e 69 6e 69 } //1 Livsfaren\Chrilless.ini
		$a_01_4 = {43 6f 75 6e 74 65 72 73 68 61 64 69 6e 67 2e 69 6e 69 } //1 Countershading.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RB_MTB_6{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 00 73 00 6e 00 69 00 6e 00 67 00 73 00 5c 00 50 00 6f 00 6c 00 69 00 74 00 69 00 64 00 69 00 72 00 65 00 6b 00 74 00 72 00 73 00 } //1 Lsnings\Politidirektrs
		$a_01_1 = {41 00 62 00 72 00 6f 00 67 00 61 00 74 00 65 00 64 00 2e 00 64 00 6c 00 6c 00 } //1 Abrogated.dll
		$a_01_2 = {53 00 6f 00 6c 00 66 00 69 00 6c 00 74 00 72 00 65 00 6e 00 65 00 2e 00 47 00 61 00 72 00 } //1 Solfiltrene.Gar
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 52 00 67 00 73 00 6b 00 79 00 73 00 5c 00 76 00 61 00 6e 00 64 00 62 00 65 00 68 00 6f 00 6c 00 64 00 65 00 72 00 73 00 } //1 Software\Rgskys\vandbeholders
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_NSISInject_RB_MTB_7{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 00 6e 00 63 00 6f 00 6e 00 74 00 65 00 6d 00 70 00 74 00 75 00 6f 00 75 00 73 00 6c 00 79 00 2e 00 50 00 72 00 6f 00 } //1 Uncontemptuously.Pro
		$a_01_1 = {4d 00 61 00 67 00 74 00 6b 00 61 00 6d 00 70 00 2e 00 75 00 74 00 61 00 } //1 Magtkamp.uta
		$a_01_2 = {44 00 65 00 6c 00 69 00 62 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 4d 00 69 00 63 00 } //1 Deliberations.Mic
		$a_01_3 = {4c 00 61 00 6d 00 70 00 61 00 64 00 69 00 74 00 65 00 2e 00 57 00 65 00 73 00 } //1 Lampadite.Wes
		$a_01_4 = {53 00 6b 00 61 00 6e 00 64 00 69 00 6e 00 61 00 76 00 69 00 73 00 65 00 72 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 36 00 39 00 5c 00 46 00 72 00 61 00 6e 00 6b 00 69 00 65 00 2e 00 6c 00 6e 00 6b 00 } //1 Skandinaviseringernes69\Frankie.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RB_MTB_8{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 00 61 00 6c 00 65 00 72 00 20 00 53 00 75 00 6e 00 64 00 6f 00 67 00 73 00 20 00 42 00 72 00 65 00 77 00 61 00 67 00 65 00 } //1 Haler Sundogs Brewage
		$a_01_1 = {42 00 6c 00 61 00 6e 00 63 00 68 00 65 00 72 00 65 00 64 00 65 00 73 00 } //1 Blancheredes
		$a_01_2 = {45 00 61 00 72 00 74 00 68 00 71 00 75 00 61 00 6b 00 65 00 20 00 6d 00 61 00 72 00 69 00 73 00 20 00 47 00 61 00 6d 00 6d 00 65 00 6e 00 } //1 Earthquake maris Gammen
		$a_01_3 = {46 00 75 00 6c 00 6d 00 69 00 6e 00 75 00 72 00 61 00 74 00 65 00 20 00 5a 00 65 00 6e 00 64 00 6f 00 } //1 Fulminurate Zendo
		$a_01_4 = {50 00 72 00 65 00 70 00 6f 00 73 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 Preposed.exe
		$a_01_5 = {53 00 6b 00 75 00 72 00 76 00 6f 00 67 00 6e 00 65 00 20 00 4e 00 6f 00 6e 00 69 00 6d 00 70 00 72 00 65 00 67 00 6e 00 61 00 74 00 65 00 64 00 } //1 Skurvogne Nonimpregnated
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}