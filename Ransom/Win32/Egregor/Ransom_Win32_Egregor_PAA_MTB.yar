
rule Ransom_Win32_Egregor_PAA_MTB{
	meta:
		description = "Ransom:Win32/Egregor.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 00 2d 00 64 00 75 00 62 00 69 00 73 00 74 00 65 00 69 00 6e 00 6d 00 75 00 74 00 74 00 65 00 72 00 66 00 69 00 63 00 6b 00 65 00 72 00 } //1 --dubisteinmutterficker
		$a_01_1 = {45 00 67 00 72 00 65 00 67 00 6f 00 72 00 } //1 Egregor
		$a_01_2 = {49 6e 74 65 72 65 73 74 69 6e 67 20 6d 6f 64 75 6c 65 } //1 Interesting module
		$a_01_3 = {48 65 6c 6c 6f 20 77 6f 72 6c 64 } //1 Hello world
		$a_01_4 = {2e 70 64 62 } //1 .pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}