
rule Ransom_Win32_ContiCrypt_KRT_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.KRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 33 45 f8 0b 47 10 83 e1 00 31 c1 8b 45 f8 03 77 14 8b 7f 0c 03 bb 58 f0 44 00 f3 a4 81 e7 00 00 00 00 03 3c e4 } //5
		$a_01_1 = {33 5d 0c 89 df 8b 5d f8 8f 45 f8 8b 4d f8 8f 45 f8 8b 75 f8 f3 a4 8f 45 f8 8b 7d f8 81 e6 00 00 00 00 33 34 e4 } //5
		$a_01_2 = {d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=6
 
}