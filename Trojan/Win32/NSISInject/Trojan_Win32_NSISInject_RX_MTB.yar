
rule Trojan_Win32_NSISInject_RX_MTB{
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