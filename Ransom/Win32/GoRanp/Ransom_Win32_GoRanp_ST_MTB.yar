
rule Ransom_Win32_GoRanp_ST_MTB{
	meta:
		description = "Ransom:Win32/GoRanp.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 61 6c 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 your all files have been encrypted
		$a_81_1 = {69 66 20 79 6f 75 20 77 61 6e 74 20 79 6f 75 20 66 69 6c 65 73 20 62 61 63 6b } //1 if you want you files back
		$a_81_2 = {65 6d 61 69 6c 20 75 73 20 68 65 72 65 20 3a } //1 email us here :
		$a_81_3 = {46 75 63 6b 20 79 6f 75 21 21 21 } //1 Fuck you!!!
		$a_81_4 = {5c 44 65 73 6b 74 6f 70 5c 46 75 63 6b 2e 74 78 74 } //1 \Desktop\Fuck.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}