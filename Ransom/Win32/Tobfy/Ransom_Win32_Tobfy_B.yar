
rule Ransom_Win32_Tobfy_B{
	meta:
		description = "Ransom:Win32/Tobfy.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 c9 0d 66 19 00 81 c1 5f f3 6e 3c 30 0c 3e } //1
		$a_01_1 = {f0 0d cd 27 b1 91 89 82 6d af c6 bb c8 bf 88 64 f0 38 24 19 c6 d6 39 52 6e 09 78 6b c5 08 7f 6d e6 a1 b9 86 d3 38 ec 33 8c 45 ab } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}