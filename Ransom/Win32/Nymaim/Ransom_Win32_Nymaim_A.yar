
rule Ransom_Win32_Nymaim_A{
	meta:
		description = "Ransom:Win32/Nymaim.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 08 00 20 20 20 } //01 00 
		$a_01_1 = {81 38 2e 74 6f 72 0f 85 } //01 00 
		$a_01_2 = {81 48 04 20 20 20 20 } //01 00 
		$a_01_3 = {81 78 04 72 65 6e 74 } //01 00 
		$a_03_4 = {66 69 6c 65 90 09 02 00 90 03 02 02 c7 03 8d 15 90 00 } //01 00 
		$a_01_5 = {c7 43 04 6e 61 6d 65 } //01 00 
		$a_01_6 = {c6 43 08 3d } //00 00 
	condition:
		any of ($a_*)
 
}