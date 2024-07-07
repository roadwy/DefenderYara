
rule Ransom_Win32_Nymaim_F{
	meta:
		description = "Ransom:Win32/Nymaim.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 06 d1 c8 40 46 49 75 } //1
		$a_01_1 = {c6 06 04 c6 46 01 01 8b 02 89 c1 } //1
		$a_01_2 = {59 83 e1 03 c1 e1 03 d3 cb 8a 07 30 d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}