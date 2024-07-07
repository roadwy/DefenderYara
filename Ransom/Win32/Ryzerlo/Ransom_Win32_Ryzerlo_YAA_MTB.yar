
rule Ransom_Win32_Ryzerlo_YAA_MTB{
	meta:
		description = "Ransom:Win32/Ryzerlo.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 d8 f6 17 89 c0 } //1
		$a_01_1 = {31 d8 80 2f 98 31 de 89 f0 } //1
		$a_01_2 = {89 d8 31 f0 80 07 53 31 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}