
rule Trojan_BAT_WhiteSnake_AWS_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.AWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 04 09 06 11 04 91 58 20 ff 00 00 00 5f 0d 06 11 04 91 13 0b 06 11 04 06 09 91 9c 06 09 11 0b 9c 06 11 04 91 06 09 91 58 20 ff 00 00 00 5f 13 0c 08 11 0a 02 11 0a 91 06 11 0c 91 61 d2 9c 00 11 0a 17 58 } //3
		$a_01_1 = {06 11 07 91 58 07 11 07 91 58 20 ff 00 00 00 5f 0d 06 11 07 91 13 08 06 11 07 06 09 91 9c 06 09 11 08 9c 00 11 07 17 58 13 07 11 07 20 00 01 00 00 fe 04 13 09 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}