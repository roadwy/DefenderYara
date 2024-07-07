
rule Ransom_Win32_Lokbit_AA_MTB{
	meta:
		description = "Ransom:Win32/Lokbit.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 6a 00 6a 90 01 01 68 02 10 04 00 ff d0 8b f0 90 00 } //1
		$a_03_1 = {bb 1a 00 00 00 be 41 00 00 90 01 01 6a 5c ff 75 90 01 01 ff 15 90 01 04 83 c4 08 83 c0 02 90 00 } //1
		$a_01_2 = {8b 4d 0c 41 33 d2 f7 f1 92 3b 45 08 } //1
		$a_01_3 = {33 c0 40 c1 e0 06 8d 40 f0 64 8b 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}