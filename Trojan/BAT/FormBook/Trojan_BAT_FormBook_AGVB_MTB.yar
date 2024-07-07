
rule Trojan_BAT_FormBook_AGVB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {4d 00 6f 00 73 00 65 00 72 00 77 00 61 00 72 00 65 00 32 00 30 00 32 00 32 00 } //1 Moserware2022
		$a_01_3 = {41 6c 6f 72 5f 32 32 } //1 Alor_22
		$a_01_4 = {62 00 72 00 6f 00 77 00 6e 00 } //1 brown
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}