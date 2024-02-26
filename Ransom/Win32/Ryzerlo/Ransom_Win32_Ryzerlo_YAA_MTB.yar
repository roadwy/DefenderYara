
rule Ransom_Win32_Ryzerlo_YAA_MTB{
	meta:
		description = "Ransom:Win32/Ryzerlo.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 d8 f6 17 89 c0 } //01 00 
		$a_01_1 = {31 d8 80 2f 98 31 de 89 f0 } //01 00 
		$a_01_2 = {89 d8 31 f0 80 07 53 31 c3 } //00 00 
	condition:
		any of ($a_*)
 
}