
rule Trojan_BAT_FormBook_NU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 08 20 00 60 00 00 5d 06 08 20 00 60 00 00 5d 91 07 08 1f 16 5d 28 fd 01 00 06 61 06 08 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //01 00 
		$a_01_1 = {01 57 df b6 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b0 00 00 00 24 00 00 00 97 00 00 00 67 02 00 00 f8 00 00 00 07 00 00 00 5e 01 00 00 04 00 00 00 43 } //00 00 
	condition:
		any of ($a_*)
 
}