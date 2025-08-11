
rule Trojan_Win32_GuLoader_ASM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 78 73 68 69 70 35 39 5c 6f 70 74 72 6e 65 6e 64 65 2e 64 6c 6c } //1 Exship59\optrnende.dll
		$a_01_1 = {42 61 61 6e 64 73 6b 69 66 74 65 72 6e 65 73 5c 70 72 6f 74 6f 68 69 73 74 6f 72 69 61 6e 5c 4b 6e 75 73 65 73 31 38 37 } //1 Baandskifternes\protohistorian\Knuses187
		$a_01_2 = {73 6f 63 69 61 6c 62 65 67 69 76 65 6e 68 65 64 65 6e 5c 68 61 6c 6c 75 63 69 6e 61 74 69 6f 6e 65 72 73 2e 64 6c 6c } //1 socialbegivenheden\hallucinationers.dll
		$a_01_3 = {70 68 79 73 6f 70 68 6f 72 65 5c 73 74 72 61 65 64 65 74 2e 69 6e 69 } //1 physophore\straedet.ini
		$a_01_4 = {47 75 6c 76 68 6a 64 65 72 6e 65 31 34 39 5c 68 65 6c 73 69 6c 6b 65 73 2e 69 6e 69 } //1 Gulvhjderne149\helsilkes.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}