
rule Trojan_BAT_Injuke_ARDA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ARDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 11 00 91 13 02 38 ?? ff ff ff 03 8e 69 17 59 13 03 38 ?? ff ff ff 03 2a 03 11 03 11 02 9c 38 4d 00 00 00 11 00 11 03 } //3
		$a_03_1 = {03 11 00 03 11 03 91 9c 20 04 00 00 00 fe 0e 01 00 38 ?? ff ff ff 16 13 00 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}