
rule Ransom_Win32_Mytreex_B_rsm{
	meta:
		description = "Ransom:Win32/Mytreex.B!rsm,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd2 00 ffffffd2 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 a0 04 04 00 6a 00 ff 15 } //100
		$a_03_1 = {6a 40 68 a0 04 04 00 [0-08] ff 15 } //100
		$a_01_2 = {b9 79 37 9e } //10
		$a_01_3 = {47 86 c8 61 } //10
	condition:
		((#a_01_0  & 1)*100+(#a_03_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=210
 
}