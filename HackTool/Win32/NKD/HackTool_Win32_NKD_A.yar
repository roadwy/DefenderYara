
rule HackTool_Win32_NKD_A{
	meta:
		description = "HackTool:Win32/NKD.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {6e 6b 64 2e 61 73 74 61 6c 61 76 69 73 74 61 2e 6d 73 } //1 nkd.astalavista.ms
		$a_01_1 = {4b 45 59 5f 45 58 50 4c 4f 49 54 20 3d 3e } //1 KEY_EXPLOIT =>
		$a_01_2 = {45 6c 20 43 72 61 62 65 20 26 20 54 65 61 4d 20 4e 4b 44 } //1 El Crabe & TeaM NKD
		$a_01_3 = {3a 2f 2f 45 6c 43 72 61 62 65 2e 42 6c 6f 67 53 70 6f 74 2e } //1 ://ElCrabe.BlogSpot.
		$a_01_4 = {6c 69 63 36 30 2e 70 70 6c } //1 lic60.ppl
		$a_01_5 = {68 69 6e 74 5f 6e 6f 70 } //1 hint_nop
		$a_01_6 = {2d 73 74 79 6c 65 20 6c 69 63 20 6c 6f 61 64 65 72 } //1 -style lic loader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}