
rule Ransom_Win32_Mehmehowi_A{
	meta:
		description = "Ransom:Win32/Mehmehowi.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 50 ff [0-06] ff [0-06] eb ?? 50 ff } //1
		$a_03_1 = {50 6a 00 6a 01 6a 13 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 6a 06 6a 00 6a 00 6a 00 68 20 04 00 c0 ff 15 } //3
		$a_03_2 = {ff ff 6a 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*3+(#a_03_2  & 1)*1) >=5
 
}