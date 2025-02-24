
rule Trojan_BAT_Nekark_NM_MTB{
	meta:
		description = "Trojan:BAT/Nekark.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 20 6c 61 7a 79 20 75 6e 69 76 65 72 73 65 20 73 68 65 20 75 6e 64 65 72 73 74 61 6e 64 } //1 she lazy universe she understand
		$a_01_1 = {71 75 69 63 6b 20 74 68 65 6d 20 77 68 69 74 65 20 74 68 65 6d 20 6f 62 6a 65 63 74 20 74 65 61 63 68 20 6d 65 20 6f 6c 64 20 74 68 65 6d 20 64 65 73 69 67 6e } //1 quick them white them object teach me old them design
		$a_01_2 = {50 61 74 72 69 63 6b 52 69 63 68 50 6c 61 79 65 72 33 32 32 50 61 74 72 69 63 6b 2e 64 6e 70 79 47 } //2 PatrickRichPlayer322Patrick.dnpyG
		$a_01_3 = {64 65 73 69 67 6e 20 69 74 20 62 6c 75 65 } //1 design it blue
		$a_01_4 = {6f 6c 64 20 69 6e 6e 6f 76 61 74 65 20 63 6f 6d 70 75 74 65 72 } //1 old innovate computer
		$a_01_5 = {62 6c 61 63 6b 20 73 6f 6c 75 74 69 6f 6e 20 73 6f 6c 76 65 } //1 black solution solve
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}