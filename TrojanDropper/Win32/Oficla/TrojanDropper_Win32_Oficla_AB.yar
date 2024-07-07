
rule TrojanDropper_Win32_Oficla_AB{
	meta:
		description = "TrojanDropper:Win32/Oficla.AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {52 52 8b 45 b4 83 e8 90 01 01 f7 d0 88 03 43 e9 90 00 } //1
		$a_03_1 = {8b 8a 00 a0 40 00 66 85 c0 74 02 d1 e1 81 f1 90 01 04 89 8c 90 01 02 ff ff ff 83 c2 04 83 fa 3c 75 de 90 00 } //1
		$a_03_2 = {00 a0 40 00 8b 9d 90 01 02 ff ff 88 d1 d3 fb 29 da 81 f2 90 01 04 89 94 90 01 02 ff ff ff 83 c0 04 83 f8 3c 75 d9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}