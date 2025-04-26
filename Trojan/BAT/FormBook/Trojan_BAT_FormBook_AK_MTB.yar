
rule Trojan_BAT_FormBook_AK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 0a 2b 56 00 07 11 08 11 0a 6f 97 00 00 0a 13 0b 11 0b 16 16 16 16 28 98 00 00 0a 28 99 00 00 0a 13 0c 11 0c 2c 2c 00 08 12 0b 28 9a 00 00 0a 6f 9b 00 00 0a 00 08 12 0b 28 9c 00 00 0a 6f 9b 00 00 0a 00 08 12 0b 28 9d 00 00 0a 6f 9b 00 00 0a 00 00 00 11 0a 17 d6 13 0a 11 0a 11 09 fe 02 16 fe 01 13 0d 11 0d 2d 9b } //2
		$a_01_1 = {46 6c 79 69 6e 67 54 68 72 6f 75 67 68 55 6e 69 76 65 72 73 65 } //1 FlyingThroughUniverse
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}