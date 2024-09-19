
rule Trojan_BAT_FormBook_NZG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 06 93 0b 06 18 58 93 07 61 0b } //2
		$a_01_1 = {11 0c 11 07 58 11 09 59 93 61 11 0b } //2
		$a_81_2 = {34 38 33 38 32 32 36 63 2d 31 31 62 37 2d 34 36 62 65 2d 39 36 37 37 2d 38 31 62 62 63 39 36 38 30 63 66 64 } //1 4838226c-11b7-46be-9677-81bbc9680cfd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}