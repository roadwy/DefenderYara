
rule Ransom_MSIL_Freak_MK_MTB{
	meta:
		description = "Ransom:MSIL/Freak.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {79 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 66 72 65 61 6b 2e 72 61 6e 73 6f 6d } //your system is infected with freak.ransom  1
		$a_80_1 = {66 72 65 61 6b 20 72 61 6e 73 6f 6d } //freak ransom  1
		$a_80_2 = {79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 70 75 62 6c 69 63 20 6b 65 79 } //your files are encrypted with public key  1
		$a_80_3 = {79 6f 75 20 63 61 6e 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b 20 62 79 20 70 61 79 69 6e 67 } //you can get your files back by paying  1
		$a_80_4 = {69 73 20 6d 79 20 63 6f 6d 70 75 74 65 72 20 64 61 6d 61 67 65 64 3f } //is my computer damaged?  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}