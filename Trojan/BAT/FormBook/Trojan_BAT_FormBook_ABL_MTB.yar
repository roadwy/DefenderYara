
rule Trojan_BAT_FormBook_ABL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 1d a2 09 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 70 00 00 00 0b 00 00 00 89 00 00 00 50 00 00 00 52 00 00 00 } //2
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 } //1 PASSWORD
		$a_01_4 = {59 00 6f 00 75 00 72 00 5f 00 46 00 72 00 69 00 65 00 6e 00 64 00 5f 00 54 00 68 00 65 00 5f 00 52 00 61 00 74 00 5f 00 69 00 63 00 6f 00 6e 00 } //1 Your_Friend_The_Rat_icon
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}