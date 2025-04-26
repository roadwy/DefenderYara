
rule Rogue_Win32_Sonfrus{
	meta:
		description = "Rogue:Win32/Sonfrus,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6f 75 76 6f 69 72 20 73 75 70 70 72 69 6d 65 72 20 6c 65 73 20 76 69 72 75 73 20 } //1 pouvoir supprimer les virus 
		$a_01_1 = {4c 65 73 20 63 6f 64 65 73 20 73 6f 6e 74 20 69 6e 76 61 6c 69 64 65 73 20 } //1 Les codes sont invalides 
		$a_01_2 = {4c 69 73 74 56 69 72 75 73 14 } //1 楌瑳楖畲ᑳ
		$a_01_3 = {26 63 6f 64 65 38 3d 00 } //1 挦摯㡥=
		$a_01_4 = {57 6f 72 6d 2e 42 61 67 67 6c 65 2e 43 50 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}