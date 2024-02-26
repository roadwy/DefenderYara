
rule Trojan_Win32_NSISInject_RC_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 90 02 95 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 ff 15 90 01 04 83 ec 1c 89 85 48 fe ff ff 8b 85 48 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RC_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 90 02 65 89 04 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 ff 15 90 01 04 83 ec 1c 89 45 b0 8b 45 b0 31 c9 89 04 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RC_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 64 65 72 66 6f 72 73 74 61 61 65 74 2e 69 6e 69 } //01 00  Underforstaaet.ini
		$a_01_1 = {54 76 72 73 74 69 6c 6c 65 64 65 2e 69 6e 69 } //01 00  Tvrstillede.ini
		$a_01_2 = {6d 61 6a 6f 72 69 73 65 72 69 6e 67 65 6e 73 2e 4e 79 6e } //01 00  majoriseringens.Nyn
		$a_01_3 = {4d 65 74 74 65 73 2e 53 69 67 } //01 00  Mettes.Sig
		$a_01_4 = {54 75 73 69 6e 64 65 74 73 2e 6c 6e 6b } //01 00  Tusindets.lnk
		$a_01_5 = {41 69 6c 75 72 6f 6d 61 6e 69 61 2e 4e 65 72 } //00 00  Ailuromania.Ner
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RC_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 6b 72 6f 73 6b 6f 70 65 72 65 2e 6c 6e 6b } //01 00  Mikroskopere.lnk
		$a_01_1 = {53 6b 75 6d 73 6c 75 6b 6b 65 72 65 6e 2e 69 6e 69 } //01 00  Skumslukkeren.ini
		$a_01_2 = {50 65 72 73 69 73 6b 2e 6c 6e 6b } //01 00  Persisk.lnk
		$a_01_3 = {72 61 66 66 69 6e 61 64 65 72 69 70 72 6f 64 75 6b 74 73 2e 69 6e 69 } //01 00  raffinaderiprodukts.ini
		$a_01_4 = {43 6f 6c 75 6d 6e 69 7a 69 6e 67 2e 64 6c 6c } //01 00  Columnizing.dll
		$a_01_5 = {73 6f 6c 69 6e 67 6b 6c 61 73 73 65 72 6e 65 73 2e 69 6e 69 } //00 00  solingklassernes.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RC_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 00 6f 00 6c 00 6f 00 6e 00 6e 00 65 00 72 00 31 00 2e 00 69 00 6e 00 69 00 } //01 00  Kolonner1.ini
		$a_01_1 = {4b 00 72 00 79 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 5c 00 56 00 6f 00 6c 00 64 00 65 00 6e 00 65 00 73 00 2e 00 48 00 61 00 69 00 } //01 00  Krystaller\Voldenes.Hai
		$a_01_2 = {65 00 72 00 72 00 65 00 6d 00 61 00 6e 00 64 00 65 00 6e 00 2e 00 46 00 6f 00 72 00 } //01 00  erremanden.For
		$a_01_3 = {47 00 6c 00 61 00 6d 00 6f 00 75 00 72 00 6c 00 65 00 73 00 73 00 2e 00 69 00 6e 00 69 00 } //00 00  Glamourless.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RC_MTB_6{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 69 00 6e 00 6f 00 6c 00 65 00 75 00 6d 00 6d 00 65 00 74 00 73 00 2e 00 6c 00 6e 00 6b 00 } //01 00  Linoleummets.lnk
		$a_01_1 = {4d 00 61 00 72 00 6b 00 65 00 64 00 73 00 61 00 6e 00 64 00 65 00 6c 00 65 00 6e 00 38 00 33 00 2e 00 69 00 6e 00 69 00 } //01 00  Markedsandelen83.ini
		$a_01_2 = {70 00 72 00 6f 00 64 00 75 00 6b 00 74 00 69 00 6f 00 6e 00 73 00 66 00 6f 00 72 00 68 00 6f 00 6c 00 64 00 2e 00 47 00 6c 00 6f 00 } //01 00  produktionsforhold.Glo
		$a_01_3 = {66 00 61 00 63 00 65 00 2d 00 6d 00 6f 00 6e 00 6b 00 65 00 79 00 2e 00 70 00 6e 00 67 00 } //01 00  face-monkey.png
		$a_01_4 = {55 00 6c 00 74 00 72 00 61 00 72 00 69 00 74 00 75 00 61 00 6c 00 69 00 73 00 6d 00 2e 00 69 00 6e 00 69 00 } //00 00  Ultraritualism.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_RC_MTB_7{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 79 00 6d 00 62 00 6f 00 6c 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 20 00 70 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 69 00 6f 00 6e 00 65 00 6e 00 73 00 20 00 6c 00 65 00 6f 00 70 00 61 00 72 00 64 00 69 00 6e 00 65 00 } //01 00  symbolography projektionens leopardine
		$a_01_1 = {73 00 74 00 61 00 72 00 74 00 67 00 74 00 20 00 6b 00 72 00 79 00 62 00 73 00 6b 00 79 00 74 00 74 00 65 00 72 00 6e 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  startgt krybskytterne.exe
		$a_01_2 = {74 00 75 00 62 00 65 00 72 00 6f 00 73 00 65 00 20 00 69 00 76 00 72 00 6b 00 73 00 74 00 74 00 65 00 72 00 65 00 6e 00 73 00 20 00 73 00 74 00 76 00 6c 00 65 00 74 00 72 00 61 00 6d 00 70 00 73 00 } //01 00  tuberose ivrkstterens stvletramps
		$a_01_3 = {64 00 69 00 73 00 70 00 61 00 70 00 61 00 6c 00 69 00 7a 00 65 00 20 00 6b 00 72 00 65 00 61 00 74 00 75 00 72 00 65 00 74 00 20 00 70 00 61 00 6c 00 69 00 75 00 72 00 75 00 73 00 } //00 00  dispapalize kreaturet paliurus
	condition:
		any of ($a_*)
 
}