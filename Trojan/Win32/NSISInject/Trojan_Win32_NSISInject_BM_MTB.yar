
rule Trojan_Win32_NSISInject_BM_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 62 65 74 72 6e 69 6e 67 5c 43 69 67 61 72 72 75 6c 6c 65 72 65 6e 73 31 35 33 5c 41 63 63 6f 6d 70 6c 65 6d 65 6e 74 5c 4d 79 6e 64 69 67 68 65 64 65 6e 73 2e 69 6e 69 } //1 Lbetrning\Cigarrullerens153\Accomplement\Myndighedens.ini
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 56 65 6b 73 65 6c 73 74 72 6d 6d 65 6e 73 5c 42 65 72 6b 65 6c 65 69 61 6e } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\Vekselstrmmens\Berkeleian
		$a_01_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 42 65 64 65 61 66 65 6e 5c 54 6a 65 6e 73 74 6c 65 64 69 67 74 5c 53 70 69 6c 64 65 76 61 6e 64 73 75 64 6c 65 64 6e 69 6e 67 } //1 CurrentVersion\Uninstall\Bedeafen\Tjenstledigt\Spildevandsudledning
		$a_01_3 = {41 73 63 61 70 65 5c 52 65 6e 73 6e 69 6e 67 73 66 6f 72 6d 65 72 6e 65 2e 69 6e 69 } //1 Ascape\Rensningsformerne.ini
		$a_01_4 = {4d 69 6e 6f 72 69 74 65 74 65 72 6e 65 73 5c 48 75 6d 75 73 5c 43 68 61 65 74 6f 70 68 6f 72 61 5c 6a 6f 72 61 6d 73 } //1 Minoriteternes\Humus\Chaetophora\jorams
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}