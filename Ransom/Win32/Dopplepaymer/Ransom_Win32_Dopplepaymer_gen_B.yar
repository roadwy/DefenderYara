
rule Ransom_Win32_Dopplepaymer_gen_B{
	meta:
		description = "Ransom:Win32/Dopplepaymer.gen!B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {7e 00 31 00 3a 00 } //1 ~1:
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 } //1 \system32\
		$a_00_2 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 } //1 \windows\
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}