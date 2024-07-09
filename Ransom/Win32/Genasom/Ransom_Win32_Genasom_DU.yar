
rule Ransom_Win32_Genasom_DU{
	meta:
		description = "Ransom:Win32/Genasom.DU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 1c 6a 00 6a 20 6a 04 6a 00 6a 01 68 00 00 00 40 52 ff d5 6a 00 8b e8 8d 44 24 14 50 57 53 55 ff } //1
		$a_01_1 = {85 c0 75 4d 6a 01 6a 1a 8d 44 24 0c 50 6a 00 ff } //1
		$a_01_2 = {8d 4c 24 58 51 ff d6 68 e8 b3 40 00 8d 54 24 58 52 ff d6 } //1
		$a_03_3 = {8d 44 24 0c 50 ff d3 8d 4c 24 0c 51 ff d5 6a 0a ff 15 ?? ?? ?? 00 6a 00 6a 00 6a 00 8d 54 24 18 52 ff d6 85 c0 75 d9 5d 5b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}