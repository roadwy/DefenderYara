
rule Ransom_Win32_Abucrosm_A{
	meta:
		description = "Ransom:Win32/Abucrosm.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //All your files are encrypted  1
		$a_80_1 = {21 21 20 52 45 41 44 20 4d 45 20 21 21 2e 74 78 74 } //!! READ ME !!.txt  1
		$a_80_2 = {2e 63 75 62 61 } //.cuba  1
		$a_80_3 = {63 75 62 61 5f 73 75 70 70 6f 72 74 40 } //cuba_support@  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}