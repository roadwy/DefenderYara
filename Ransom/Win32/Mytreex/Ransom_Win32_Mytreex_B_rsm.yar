
rule Ransom_Win32_Mytreex_B_rsm{
	meta:
		description = "Ransom:Win32/Mytreex.B!rsm,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd2 00 ffffffd2 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {68 a0 04 04 00 6a 00 ff 15 } //64 00 
		$a_03_1 = {6a 40 68 a0 04 04 00 90 02 08 ff 15 90 00 } //0a 00 
		$a_01_2 = {b9 79 37 9e } //0a 00 
		$a_01_3 = {47 86 c8 61 } //00 00 
	condition:
		any of ($a_*)
 
}