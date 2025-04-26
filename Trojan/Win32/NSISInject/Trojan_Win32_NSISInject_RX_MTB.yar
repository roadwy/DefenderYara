
rule Trojan_Win32_NSISInject_RX_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 61 6e 64 6c 67 65 6b 6c 69 6e 69 6b 6b 65 72 32 31 32 2e 6d 61 72 } //1 Tandlgeklinikker212.mar
		$a_01_1 = {43 3a 5c 54 45 4d 50 5c 6f 76 65 72 6d 61 6e 64 65 64 65 5c 4d 65 74 72 61 6e } //1 C:\TEMP\overmandede\Metran
		$a_01_2 = {53 59 53 54 45 4d 33 32 5c 65 6e 65 72 67 65 74 69 73 6b 65 73 5c 50 68 79 73 69 63 69 61 6e 65 72 32 32 33 2e 6c 6e 6b } //1 SYSTEM32\energetiskes\Physicianer223.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_NSISInject_RX_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 6e 00 69 00 66 00 6e 00 69 00 6e 00 67 00 73 00 35 00 39 00 5c 00 47 00 6c 00 61 00 6e 00 73 00 72 00 6f 00 6c 00 6c 00 65 00 6e 00 2e 00 49 00 6e 00 65 00 } //1 Snifnings59\Glansrollen.Ine
		$a_01_1 = {66 00 6c 00 61 00 61 00 64 00 6e 00 69 00 6e 00 67 00 65 00 72 00 2e 00 69 00 6e 00 69 00 } //1 flaadninger.ini
		$a_01_2 = {53 00 71 00 75 00 69 00 72 00 61 00 72 00 63 00 68 00 79 00 2e 00 41 00 66 00 66 00 } //1 Squirarchy.Aff
		$a_01_3 = {45 00 74 00 61 00 74 00 73 00 72 00 61 00 61 00 64 00 73 00 2e 00 53 00 6c 00 61 00 } //1 Etatsraads.Sla
		$a_01_4 = {74 00 6f 00 69 00 6c 00 65 00 74 00 74 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //1 toilettes.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}