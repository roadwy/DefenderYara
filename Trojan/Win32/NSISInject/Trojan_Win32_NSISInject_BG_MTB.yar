
rule Trojan_Win32_NSISInject_BG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 79 5c 53 74 61 64 69 6f 6e 65 74 5c 53 6c 69 70 70 65 72 69 65 73 74 2e 53 65 6c } //1 softy\Stadionet\Slipperiest.Sel
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4c 69 73 74 65 61 66 73 74 65 6d 6e 69 6e 67 65 72 6e 65 5c 47 72 65 65 6b 6c 69 6e 67 } //1 Software\Listeafstemningerne\Greekling
		$a_01_2 = {45 63 62 6f 6c 69 63 5c 41 72 74 79 5c 47 72 61 76 73 74 65 6e 32 33 33 2e 6c 6e 6b } //1 Ecbolic\Arty\Gravsten233.lnk
		$a_01_3 = {48 65 61 64 6c 6f 6e 67 77 69 73 65 5c 6c 61 6e 64 73 70 6c 61 6e 6c 67 6e 69 6e 67 65 72 6e 65 5c 45 67 65 6c 76 65 74 5c 49 6e 66 6f 72 6d 61 74 69 6f 6e 73 73 74 72 6d 73 2e 46 6a 6c } //1 Headlongwise\landsplanlgningerne\Egelvet\Informationsstrms.Fjl
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4e 69 6e 65 74 74 73 5c 50 72 65 64 69 63 74 69 76 65 6e 65 73 73 5c 42 61 73 6e 67 6c 65 6e 73 } //1 Software\Ninetts\Predictiveness\Basnglens
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}