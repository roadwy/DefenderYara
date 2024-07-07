
rule Ransom_Win32_Crysis_PB_MTB{
	meta:
		description = "Ransom:Win32/Crysis.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 ff 69 04 00 00 75 90 01 01 6a 00 ff d3 6a 00 ff 15 90 01 04 6a 00 6a 00 6a 00 ff 15 90 01 04 6a 00 90 05 10 02 6a 00 ff 15 90 01 04 e8 90 01 04 8b 4d 08 30 04 0e 46 3b f7 7c 90 00 } //10
		$a_02_1 = {69 c9 fd 43 03 00 89 0d 90 01 04 81 05 90 01 04 c3 9e 26 00 81 3d 90 01 04 a5 02 00 00 8b 35 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1) >=11
 
}