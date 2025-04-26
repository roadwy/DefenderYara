
rule Ransom_Win32_Conti_WEN_MTB{
	meta:
		description = "Ransom:Win32/Conti.WEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c0 66 c7 45 90 74 00 30 5c 05 85 40 83 f8 0c 73 05 8a 5d 84 } //1
		$a_01_1 = {30 8c 05 75 ff ff ff 40 83 f8 0c 73 08 8a 8d 74 } //1
		$a_01_2 = {88 5d e0 32 f0 88 65 e1 32 f8 88 75 e3 b1 7f 88 7d e4 32 c8 c6 45 e6 00 b5 25 88 4d de 32 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}