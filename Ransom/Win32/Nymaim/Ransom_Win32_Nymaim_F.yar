
rule Ransom_Win32_Nymaim_F{
	meta:
		description = "Ransom:Win32/Nymaim.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 06 d1 c8 40 46 49 75 } //01 00 
		$a_01_1 = {c6 06 04 c6 46 01 01 8b 02 89 c1 } //01 00 
		$a_01_2 = {59 83 e1 03 c1 e1 03 d3 cb 8a 07 30 d8 } //00 00 
		$a_00_3 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}