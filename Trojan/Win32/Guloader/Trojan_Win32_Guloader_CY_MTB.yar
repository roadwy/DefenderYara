
rule Trojan_Win32_Guloader_CY_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 6e 64 65 72 62 69 6e 64 69 6e 67 65 72 6e 65 2e 6b 6f 6e } //2 underbindingerne.kon
		$a_01_1 = {52 65 76 65 6e 74 75 72 65 31 37 35 2e 72 61 75 } //2 Reventure175.rau
		$a_01_2 = {70 72 6f 70 61 6e 67 61 73 2e 6c 65 6d } //1 propangas.lem
		$a_01_3 = {73 79 6e 6c 69 67 65 72 65 73 2e 74 78 74 } //1 synligeres.txt
		$a_01_4 = {66 61 72 63 65 73 2e 61 62 73 } //1 farces.abs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}