
rule Trojan_Win32_NSISInject_RH_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 00 09 3d 00 6a 00 ff 15 90 01 04 89 45 f4 83 7d f4 00 75 07 90 02 20 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8b 4d 10 51 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RH_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 89 45 b0 8b 45 10 68 00 00 00 80 50 ff 15 90 01 04 8b f0 6a 00 56 ff 15 90 01 04 6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RH_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6b 6f 72 70 6f 72 65 72 65 64 65 73 2e 6c 6e 6b } //1 Inkorporeredes.lnk
		$a_01_1 = {46 65 6c 69 6e 65 73 2e 64 6c 6c } //1 Felines.dll
		$a_01_2 = {55 6e 69 6e 73 74 61 6c 6c 5c 50 72 65 68 65 6e 73 69 76 65 5c 49 6e 64 65 73 70 72 72 69 6e 67 65 72 6e 65 73 } //1 Uninstall\Prehensive\Indesprringernes
		$a_01_3 = {56 61 67 65 72 62 6a 65 2e 69 6e 69 } //1 Vagerbje.ini
		$a_01_4 = {46 75 6e 6b 74 69 6f 6e 72 6c 6f 76 65 6e 65 6e 2e 42 6c 6f } //1 Funktionrlovenen.Blo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_NSISInject_RH_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 00 64 00 73 00 67 00 6e 00 69 00 6e 00 67 00 65 00 72 00 2e 00 69 00 6e 00 69 00 } //1 Udsgninger.ini
		$a_01_1 = {47 00 65 00 72 00 6e 00 69 00 6e 00 67 00 73 00 73 00 74 00 65 00 64 00 65 00 72 00 6e 00 65 00 2e 00 69 00 6e 00 69 00 } //1 Gerningsstederne.ini
		$a_01_2 = {53 00 70 00 75 00 72 00 6c 00 2e 00 69 00 6e 00 69 00 } //1 Spurl.ini
		$a_01_3 = {41 00 63 00 74 00 69 00 6e 00 69 00 64 00 69 00 61 00 63 00 65 00 61 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 Actinidiaceae.dll
		$a_01_4 = {77 00 68 00 69 00 74 00 65 00 74 00 69 00 70 00 2e 00 6c 00 6e 00 6b 00 } //1 whitetip.lnk
		$a_01_5 = {53 00 74 00 72 00 65 00 73 00 73 00 6c 00 65 00 73 00 73 00 6e 00 65 00 73 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 Stresslessness.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_NSISInject_RH_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 00 70 00 69 00 74 00 68 00 65 00 74 00 2e 00 69 00 6e 00 69 00 } //1 Epithet.ini
		$a_01_1 = {4d 00 6f 00 72 00 61 00 6c 00 69 00 7a 00 69 00 6e 00 67 00 6c 00 79 00 2e 00 64 00 6c 00 6c 00 } //1 Moralizingly.dll
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 44 00 65 00 6e 00 61 00 72 00 63 00 6f 00 74 00 69 00 7a 00 65 00 } //1 Software\Denarcotize
		$a_01_3 = {56 00 65 00 6e 00 73 00 6b 00 61 00 62 00 73 00 61 00 66 00 74 00 61 00 6c 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //1 Venskabsaftales.ini
		$a_01_4 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 46 00 69 00 73 00 68 00 77 00 6f 00 6d 00 61 00 6e 00 } //1 Uninstall\Fishwoman
		$a_01_5 = {4b 00 6f 00 6e 00 66 00 69 00 64 00 65 00 6e 00 73 00 69 00 6e 00 74 00 65 00 72 00 76 00 61 00 6c 00 6c 00 65 00 74 00 73 00 2e 00 4d 00 69 00 61 00 } //1 Konfidensintervallets.Mia
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}