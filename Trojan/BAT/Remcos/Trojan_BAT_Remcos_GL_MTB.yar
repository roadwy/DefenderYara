
rule Trojan_BAT_Remcos_GL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //1 .edom SOD ni nur eb tonnac margorp sihT!
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_03_2 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-05] 2e 65 78 65 } //1
		$a_81_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_4 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_81_5 = {63 6f 6c 65 72 2e } //1 coler.
		$a_81_6 = {63 72 73 72 2e } //1 crsr.
		$a_81_7 = {74 78 65 74 2e } //1 txet.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}