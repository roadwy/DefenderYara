
rule Ransom_Win32_MakopCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/MakopCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 8d 84 24 90 01 04 50 ff d7 6a 00 8d 44 24 4c 50 ff d3 6a 00 ff d5 a1 90 01 04 81 fe 90 01 04 0f 44 05 90 01 04 46 a3 90 01 04 81 fe 90 01 04 7c 90 01 01 ff d0 90 00 } //2
		$a_02_1 = {33 f3 c7 44 24 14 00 00 00 00 33 f7 8b 7c 24 1c 2b fe 89 7c 24 1c 25 90 01 04 81 6c 24 14 90 01 04 bb 90 01 04 81 44 24 14 90 01 04 8b 4c 24 14 8b d7 d3 e2 8b c7 03 54 24 24 c1 e8 05 03 44 24 30 33 d0 c7 05 90 01 04 00 00 00 00 8b 44 24 18 03 c7 33 d0 2b ea 8b 15 90 01 04 81 fa 90 01 04 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}