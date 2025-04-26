
rule Ransom_Win32_Eloba_A{
	meta:
		description = "Ransom:Win32/Eloba.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 65 6c 70 40 61 6e 74 69 76 69 72 75 73 65 62 6f 6c 61 2e 63 6f 6d 00 } //1
		$a_01_1 = {64 65 6e 67 65 2e 62 61 74 63 61 76 65 2e 6e 65 74 2f 67 61 7a 61 2f } //1 denge.batcave.net/gaza/
		$a_01_2 = {64 61 79 72 69 79 7a 79 69 74 68 2e 63 6f 6d 65 7a 65 2e 63 6f 6d 2f } //1 dayriyzyith.comeze.com/
		$a_01_3 = {65 62 6f 6c 61 2e 62 6d 70 00 } //1
		$a_01_4 = {32 33 63 65 30 31 32 37 2d 35 65 33 35 2d 34 62 39 61 2d 61 61 32 64 2d 35 64 61 62 36 65 66 63 38 39 30 35 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}