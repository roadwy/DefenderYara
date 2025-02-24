
rule Trojan_BAT_FormBook_MBWO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 1f 10 5d 04 07 d8 b5 9d 02 03 04 07 05 28 ?? 00 00 06 07 17 d6 0b } //3
		$a_01_1 = {06 17 07 1e 5d 1f 1f 5f 62 60 0a 02 03 07 91 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}