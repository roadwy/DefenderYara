
rule Ransom_Win32_Genasom_V{
	meta:
		description = "Ransom:Win32/Genasom.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 cd 66 0f b6 c0 41 66 89 02 8a 01 83 c2 02 3c cd 75 ed 33 c9 } //1
		$a_01_1 = {0f b7 01 66 83 f8 2a 74 06 66 89 02 83 c2 02 83 c1 02 66 83 39 00 75 e8 } //1
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 78 73 74 6f 70 69 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}