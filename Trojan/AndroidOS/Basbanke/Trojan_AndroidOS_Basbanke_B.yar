
rule Trojan_AndroidOS_Basbanke_B{
	meta:
		description = "Trojan:AndroidOS/Basbanke.B,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 43 6f 79 39 30 2e 68 74 6d 6c } //2 /Coy90.html
		$a_00_1 = {78 54 65 6c 61 43 6f 6e 74 69 6e 75 61 3a 63 6f 79 3a 61 61 61 } //2 xTelaContinua:coy:aaa
		$a_00_2 = {45 78 65 63 75 63 6f 65 73 69 6e 69 63 69 6f 75 } //2 Execucoesiniciou
		$a_00_3 = {41 64 64 4f 76 65 72 6c 61 79 5f 41 } //2 AddOverlay_A
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}