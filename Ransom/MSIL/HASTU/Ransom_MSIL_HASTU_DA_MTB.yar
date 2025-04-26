
rule Ransom_MSIL_HASTU_DA_MTB{
	meta:
		description = "Ransom:MSIL/HASTU.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 41 53 54 55 52 61 6d 73 6f 77 61 72 65 } //1 HASTURamsoware
		$a_81_1 = {45 6e 63 72 79 70 74 65 64 4b 65 79 } //1 EncryptedKey
		$a_81_2 = {6b 69 6c 6c 73 77 69 74 63 68 2e 70 68 70 } //1 killswitch.php
		$a_81_3 = {77 61 6c 6c 70 61 70 65 72 2e 62 6d 70 } //1 wallpaper.bmp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}