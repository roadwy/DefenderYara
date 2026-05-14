
rule Ransom_Win64_Mallox_MX_MTB{
	meta:
		description = "Ransom:Win64/Mallox.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files has been encrypted
		$a_01_1 = {66 72 65 65 20 64 65 63 79 72 70 74 69 6f 6e } //1 free decyrption
		$a_01_2 = {54 6f 20 72 65 63 6f 76 65 72 } //1 To recover
		$a_01_3 = {24 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 7e 00 62 00 74 00 } //1 $windows.~bt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}