
rule Ransom_Win32_Genasom_CX{
	meta:
		description = "Ransom:Win32/Genasom.CX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {5c 6f 75 6e 64 [0-03] 2e 65 78 65 } //1
		$a_03_1 = {73 74 61 72 74 20 6f 75 6e 64 [0-03] 2e 65 78 65 } //1
		$a_03_2 = {68 00 04 00 00 8d 44 24 04 50 e8 ?? ?? ?? ?? 8b c3 8b d4 b9 01 04 00 00 e8 ?? ?? ?? ?? 81 c4 04 04 00 00 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*3) >=4
 
}