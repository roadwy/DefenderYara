
rule Trojan_BAT_Seraph_GFA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 45 6f 77 50 66 35 39 71 7a 6d 77 58 64 4a 76 62 43 4a 4c 4f 76 51 6b 75 4c 62 47 59 38 64 6b } //2 3EowPf59qzmwXdJvbCJLOvQkuLbGY8dk
		$a_80_1 = {56 75 73 67 72 6e 6d 79 6b 64 7a 72 64 79 78 67 70 6e 77 74 65 7a 70 } //Vusgrnmykdzrdyxgpnwtezp  2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_01_3 = {49 6e 76 6f 6b 65 } //2 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}