
rule Trojan_BAT_FormBook_ARM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 16 13 06 2b 10 08 11 06 02 07 11 06 58 91 9c 11 06 17 58 13 06 11 06 08 8e 69 32 e9 } //3
		$a_03_1 = {0a 16 0d 2b 44 17 13 04 16 13 05 2b 1f 02 09 11 05 58 91 72 01 00 00 70 11 05 28 ?? 00 00 0a 2e 05 16 13 04 2b 14 11 05 17 58 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}