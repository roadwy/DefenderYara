
rule Trojan_BAT_FormBook_ABK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b4 9c 00 2b 0d 00 07 11 04 07 11 04 91 17 da b4 9c 00 11 04 17 d6 13 04 11 04 09 31 ae } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_ABK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 28 16 0b 2b 0e 02 06 07 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 e0 } //2
		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0a 06 05 28 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_ABK_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 58 0b 2b 49 07 06 8e 69 5d 13 04 07 09 6f ?? ?? ?? 0a 5d 13 09 06 11 04 91 13 0a 09 11 09 6f ?? ?? ?? 0a 13 0b 02 06 07 28 ?? ?? ?? 06 13 0c 02 11 0a 11 0b 11 0c 28 ?? ?? ?? 06 13 0d 06 11 04 02 11 0d 28 ?? ?? ?? 06 9c 07 17 59 0b 07 16 fe 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}