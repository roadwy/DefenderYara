
rule Trojan_Win32_Popureb_F{
	meta:
		description = "Trojan:Win32/Popureb.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 61 73 73 5f 75 72 6c 00 } //1
		$a_01_1 = {57 6e 64 70 65 72 41 64 00 } //1
		$a_01_2 = {52 75 6e 44 65 6c 61 79 54 69 6d 65 00 } //1
		$a_01_3 = {68 8d 34 10 e5 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=5
 
}