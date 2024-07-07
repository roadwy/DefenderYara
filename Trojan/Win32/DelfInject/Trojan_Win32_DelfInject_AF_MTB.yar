
rule Trojan_Win32_DelfInject_AF_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {73 70 69 72 61 6c 62 75 6e 64 65 6e 65 } //spiralbundene  3
		$a_80_1 = {62 72 69 73 74 6c 65 72 } //bristler  3
		$a_80_2 = {45 44 4c 49 4e } //EDLIN  3
		$a_80_3 = {64 6f 73 65 72 73 } //dosers  3
		$a_80_4 = {55 64 6c 65 6a 6e 69 6e 67 73 65 6a 65 6e 64 6f 6d 6d 65 6e 39 } //Udlejningsejendommen9  3
		$a_80_5 = {4b 75 72 76 65 72 6e 65 } //Kurverne  3
		$a_80_6 = {73 70 72 69 6e 67 6e 69 6e 67 65 72 6e 65 73 } //springningernes  3
		$a_80_7 = {53 6c 61 73 6b 65 64 75 6b 6b 65 6e 37 } //Slaskedukken7  3
		$a_80_8 = {53 77 61 72 6d 73 35 } //Swarms5  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}