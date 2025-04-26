
rule Trojan_BAT_Bobik_GNC_MTB{
	meta:
		description = "Trojan:BAT/Bobik.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6f 74 20 64 65 76 61 73 20 64 6e 61 20 6e 65 6b 61 74 20 74 6f 68 73 6e 65 65 72 63 53 } //ot devas dna nekat tohsneercS  1
		$a_80_1 = {64 65 74 65 6c 70 6d 6f 63 20 79 6c 6c 75 66 73 73 65 63 63 75 73 20 72 65 6c 65 64 75 68 63 73 20 6b 73 61 74 20 6f 74 20 70 75 74 72 61 74 73 20 6f 74 20 67 6e 69 79 70 6f 43 } //detelpmoc yllufsseccus releduhcs ksat ot putrats ot gniypoC  1
		$a_80_2 = {57 39 79 5a 32 78 68 59 32 39 73 49 48 52 6c 62 69 41 6d 49 43 4d 6a 49 79 4e 77 64 57 39 79 52 79 42 73 59 57 4e 76 54 43 4d 6a 49 79 } //W9yZ2xhY29sIHRlbiAmICMjIyNwdW9yRyBsYWNvTCMjIy  1
		$a_80_3 = {42 6c 62 57 46 75 63 6d 56 6b 61 58 5a 76 63 6e 41 73 62 6d 39 70 64 48 42 70 63 6d } //BlbWFucmVkaXZvcnAsbm9pdHBpcm  1
		$a_80_4 = {45 78 65 6c 61 2e 65 78 65 } //Exela.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}