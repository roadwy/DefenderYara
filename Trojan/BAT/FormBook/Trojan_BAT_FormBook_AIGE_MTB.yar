
rule Trojan_BAT_FormBook_AIGE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AIGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 00 07 15 58 } //2
		$a_01_1 = {42 00 61 00 6e 00 61 00 6e 00 61 00 48 00 6f 00 6f 00 6b 00 } //1 BananaHook
		$a_01_2 = {47 00 34 00 44 00 35 00 34 00 43 00 37 00 44 00 34 00 38 00 41 00 35 00 37 00 45 00 34 00 37 00 59 00 38 00 37 00 48 00 42 00 34 00 } //1 G4D54C7D48A57E47Y87HB4
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}